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
	"github.com/sigstore/rekor/cmd/rekor-cli/app/sharding"
	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/types"
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
	PreRun: func(cmd *cobra.Command, args []string) {
		// these are bound here so that they are not overwritten by other commands
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.CliLogger.Fatal("Error initializing cmd line args: ", err)
		}
	},
	Run: format.WrapCmd(func(args []string) (interface{}, error) {
		rekorClient, err := client.GetRekorClient(viper.GetString("rekor_server"))
		if err != nil {
			return nil, err
		}

		logIndex := viper.GetString("log-index")
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
			for ix, entry := range resp.Payload {
				if verified, err := verifyLogEntry(context.Background(), rekorClient, entry); err != nil || !verified {
					return nil, fmt.Errorf("unable to verify entry was added to log %w", err)
				}

				return parseEntry(ix, entry)
			}
		}

		uuid := viper.GetString("uuid")
		if uuid != "" {
			params := entries.NewGetLogEntryByUUIDParams()
			params.SetTimeout(viper.GetDuration("timeout"))
			if len(uuid) == sharding.UUIDLen {
				params.EntryUUID = uuid
			} else if len(uuid) == sharding.FullIDLen {
				params.EntryUUID = uuid[sharding.FullIDLen-sharding.UUIDLen:]
			} else {
				return nil, fmt.Errorf("invalid UUID length: %v", len(uuid))
			}

			resp, err := rekorClient.Entries.GetLogEntryByUUID(params)
			if err != nil {
				return nil, err
			}

			for k, entry := range resp.Payload {
				if k != params.EntryUUID {
					continue
				}

				if verified, err := verifyLogEntry(context.Background(), rekorClient, entry); err != nil || !verified {
					return nil, fmt.Errorf("unable to verify entry was added to log %w", err)
				}

				return parseEntry(k, entry)
			}
		}

		return nil, errors.New("either --uuid or --log-index must be specified")
	}),
}

func parseEntry(uuid string, e models.LogEntryAnon) (interface{}, error) {
	b, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return nil, err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}
	eimpl, err := types.NewEntry(pe)
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
		obj.AttestationType = e.Attestation.MediaType
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
