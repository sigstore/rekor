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
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"os"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-openapi/swag"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/pkg/errors"
	"github.com/sigstore/rekor/cmd/rekor-cli/app/format"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/util"
)

type uploadCmdOutput struct {
	AlreadyExists bool
	Location      string
	Index         int64
}

func (u *uploadCmdOutput) String() string {
	if u.AlreadyExists {
		return fmt.Sprintf("Entry already exists; available at: %v%v\n", viper.GetString("rekor_server"), u.Location)
	}
	return fmt.Sprintf("Created entry at index %d, available at: %v%v\n", u.Index, viper.GetString("rekor_server"), u.Location)
}

// uploadCmd represents the upload command
var uploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Upload an artifact to Rekor",
	PreRun: func(cmd *cobra.Command, args []string) {
		// these are bound here so that they are not overwritten by other commands
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.Logger.Fatal("Error initializing cmd line args: ", err)
		}
		if err := validateArtifactPFlags(false, false); err != nil {
			log.Logger.Error(err)
			_ = cmd.Help()
			os.Exit(1)
		}
	},
	Long: `This command takes the public key, signature and URL of the release artifact and uploads it to the rekor server.`,
	Run: format.WrapCmd(func(args []string) (interface{}, error) {
		ctx := context.Background()
		rekorClient, err := GetRekorClient(viper.GetString("rekor_server"))
		if err != nil {
			return nil, err
		}
		params := entries.NewCreateLogEntryParams()

		var entry models.ProposedEntry
		switch viper.GetString("type") {
		case "rekord":
			entry, err = CreateRekordFromPFlags()
			if err != nil {
				return nil, err
			}
		case "rpm":
			entry, err = CreateRpmFromPFlags()
			if err != nil {
				return nil, err
			}
		case "jar":
			entry, err = CreateJarFromPFlags()
			if err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("unknown type specified")
		}

		params.SetProposedEntry(entry)

		resp, err := rekorClient.Entries.CreateLogEntry(params)
		if err != nil {
			switch e := err.(type) {
			case *entries.CreateLogEntryConflict:
				return &uploadCmdOutput{
					Location:      e.Location.String(),
					AlreadyExists: true,
				}, nil
			default:
				return nil, err
			}
		}

		var newIndex int64
		var logEntry models.LogEntryAnon
		for _, entry := range resp.Payload {
			newIndex = swag.Int64Value(entry.LogIndex)
			logEntry = entry
		}

		// verify log entry
		if verified, err := verifyLogEntry(ctx, rekorClient, logEntry); err != nil || !verified {
			return nil, errors.Wrap(err, "unable to verify entry was added to log")
		}

		return &uploadCmdOutput{
			Location: string(resp.Location),
			Index:    newIndex,
		}, nil
	}),
}

func verifyLogEntry(ctx context.Context, rekorClient *client.Rekor, logEntry models.LogEntryAnon) (bool, error) {
	if logEntry.Verification == nil {
		return false, nil
	}
	// verify the entry
	le := &models.LogEntryAnon{
		IntegratedTime: logEntry.IntegratedTime,
		LogIndex:       logEntry.LogIndex,
		Body:           logEntry.Body,
		LogID:          logEntry.LogID,
	}

	payload, err := le.MarshalBinary()
	if err != nil {
		return false, err
	}
	canonicalized, err := jsoncanonicalizer.Transform(payload)
	if err != nil {
		return false, err
	}

	// get rekor's public key
	rekorPubKey, err := util.PublicKey(ctx, rekorClient)
	if err != nil {
		return false, err
	}

	// verify the SET against the public key
	hash := sha256.Sum256(canonicalized)
	if !ecdsa.VerifyASN1(rekorPubKey, hash[:], []byte(logEntry.Verification.SignedEntryTimestamp)) {
		return false, fmt.Errorf("unable to verify")
	}
	return true, nil
}

func init() {
	if err := addArtifactPFlags(uploadCmd); err != nil {
		log.Logger.Fatal("Error parsing cmd line args:", err)
	}

	rootCmd.AddCommand(uploadCmd)
}
