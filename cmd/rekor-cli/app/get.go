//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/sigstore/rekor/cmd/rekor-cli/app/format"
	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/tle"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/verify"
)

type getCmdOutput struct {
	Attestation     string
	AttestationType string
	Body            interface{}
	LogIndex        int
	IntegratedTime  int64
	UUID            string
	LogID           string
}

func (g *getCmdOutput) String() string {
	s := fmt.Sprintf("LogID: %v\n", g.LogID)

	if g.Attestation != "" {
		s += fmt.Sprintf("Attestation: %s\n", g.Attestation)
	}

	s += fmt.Sprintf("Index: %d\n", g.LogIndex)
	dt := time.Unix(g.IntegratedTime, 0).UTC().Format(time.RFC3339)
	s += fmt.Sprintf("IntegratedTime: %s\n", dt)
	s += fmt.Sprintf("UUID: %s\n", g.UUID)
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetIndent("", "  ")
	_ = e.Encode(g.Body)
	s += fmt.Sprintf("Body: %s\n", b.Bytes())
	return s
}

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Rekor get command",
	Long:  `Get information regarding entries in the transparency log`,
	PreRun: func(cmd *cobra.Command, _ []string) {
		// these are bound here so that they are not overwritten by other commands
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.CliLogger.Fatalf("Error initializing cmd line args: %w", err)
		}
	},
	Run: format.WrapCmd(func(_ []string) (interface{}, error) {
		ctx := context.Background()
		rekorClient, err := client.GetRekorClient(viper.GetString("rekor_server"), client.WithUserAgent(UserAgent()), client.WithRetryCount(viper.GetUint("retry")), client.WithLogger(log.CliLogger))
		if err != nil {
			return nil, err
		}

		logIndex := viper.GetString("log-index")
		uuid := viper.GetString("uuid")
		if logIndex == "" && uuid == "" {
			return nil, errors.New("either --uuid or --log-index must be specified")
		}
		// retrieve rekor pubkey for verification
		verifier, err := loadVerifier(rekorClient)
		if err != nil {
			return nil, fmt.Errorf("retrieving rekor public key")
		}

		if logIndex != "" {
			params := entries.NewGetLogEntryByIndexParams()
			params.SetTimeout(viper.GetDuration("timeout"))
			logIndexInt, err := strconv.ParseInt(logIndex, 10, 0)
			if err != nil {
				return nil, fmt.Errorf("error parsing --log-index: %w", err)
			}
			params.LogIndex = logIndexInt

			resp, err := rekorClient.Entries.GetLogEntryByIndex(params)
			if err != nil {
				return nil, err
			}
			var e models.LogEntryAnon
			for ix, entry := range resp.Payload {
				// verify log entry
				e = entry
				if err := verify.VerifyLogEntry(ctx, &e, verifier); err != nil {
					return nil, fmt.Errorf("unable to verify entry was added to log: %w", err)
				}

				// verify checkpoint
				if entry.Verification.InclusionProof.Checkpoint != nil {
					if err := verify.VerifyCheckpointSignature(&e, verifier); err != nil {
						return nil, err
					}
				}

				return parseEntry(ix, entry)
			}
		}

		// Note: this UUID may be an EntryID
		if uuid != "" {
			params := entries.NewGetLogEntryByUUIDParams()
			params.SetTimeout(viper.GetDuration("timeout"))
			params.EntryUUID = uuid

			resp, err := rekorClient.Entries.GetLogEntryByUUID(params)
			if err != nil {
				return nil, err
			}

			var e models.LogEntryAnon
			for k, entry := range resp.Payload {
				if err := compareEntryUUIDs(params.EntryUUID, k); err != nil {
					return nil, err
				}

				// verify log entry
				e = entry
				if err := verify.VerifyLogEntry(ctx, &e, verifier); err != nil {
					return nil, fmt.Errorf("unable to verify entry was added to log: %w", err)
				}

				return parseEntry(k, entry)
			}
		}

		return nil, errors.New("entry not found")
	}),
}

// TODO: Move this to the verify pkg, but only after sharding cleans
// up it's Trillian client dependency.
func compareEntryUUIDs(requestEntryUUID string, responseEntryUUID string) error {
	requestUUID, err := sharding.GetUUIDFromIDString(requestEntryUUID)
	if err != nil {
		return err
	}
	responseUUID, err := sharding.GetUUIDFromIDString(responseEntryUUID)
	if err != nil {
		return err
	}
	// Compare UUIDs.
	if requestUUID != responseUUID {
		return fmt.Errorf("unexpected entry returned from rekor server: expected %s, got %s", requestEntryUUID, responseEntryUUID)
	}
	// If the request contains a Tree ID, then compare that.
	requestTreeID, err := sharding.GetTreeIDFromIDString(requestEntryUUID)
	if err != nil {
		if errors.Is(err, sharding.ErrPlainUUID) {
			// The request did not contain a Tree ID, we're good.
			return nil
		}
		// The request had a bad Tree ID, error out.
		return err
	}
	// We requested an entry from a given Tree ID.
	responseTreeID, err := sharding.GetTreeIDFromIDString(responseEntryUUID)
	if err != nil {
		if errors.Is(err, sharding.ErrPlainUUID) {
			// The response does not contain a Tree ID, we can only do so much.
			// Old rekor instances may not have returned one.
			return nil
		}
		return err
	}
	// We have Tree IDs. Compare.
	if requestTreeID != responseTreeID {
		return fmt.Errorf("unexpected entry returned from rekor server: expected %s, got %s", requestEntryUUID, responseEntryUUID)
	}
	return nil
}

func parseEntry(uuid string, e models.LogEntryAnon) (interface{}, error) {
	if viper.GetString("format") == "tle" {
		return tle.GenerateTransparencyLogEntry(e)
	}

	b, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return nil, err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}
	eimpl, err := types.UnmarshalEntry(pe)
	if err != nil {
		return nil, err
	}

	obj := getCmdOutput{
		Body:           eimpl,
		UUID:           uuid,
		IntegratedTime: *e.IntegratedTime,
		LogIndex:       int(*e.LogIndex),
		LogID:          *e.LogID,
	}

	if e.Attestation != nil {
		obj.Attestation = string(e.Attestation.Data)
	}

	return &obj, nil
}

func init() {
	initializePFlagMap()
	if err := addUUIDPFlags(getCmd, false); err != nil {
		log.CliLogger.Fatal("Error parsing cmd line args: ", err)
	}
	if err := addLogIndexFlag(getCmd, false); err != nil {
		log.CliLogger.Fatal("Error parsing cmd line args: ", err)
	}

	rootCmd.AddCommand(getCmd)
}
