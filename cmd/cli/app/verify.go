/*
Copyright © 2020 Luke Hinds <lhinds@redhat.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package app

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"os"
	"strconv"

	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/projectrekor/rekor/cmd/cli/app/format"
	"github.com/projectrekor/rekor/pkg/generated/client/entries"
	"github.com/projectrekor/rekor/pkg/generated/models"
	"github.com/projectrekor/rekor/pkg/log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type verifyCmdOutput struct {
	RootHash  string
	EntryUUID string
	Index     int64
	Size      int64
	Hashes    []string
}

func (v *verifyCmdOutput) String() string {
	s := fmt.Sprintf("Current Root Hash: %v\n", v.RootHash)
	s += fmt.Sprintf("Entry Hash: %v\n", v.EntryUUID)
	s += fmt.Sprintf("Entry Index: %v\n", v.Index)
	s += fmt.Sprintf("Current Tree Size: %v\n\n", v.Size)

	s += "Inclusion Proof:\n"
	hasher := rfc6962.DefaultHasher
	inner := bits.Len64(uint64(v.Index ^ (v.Size - 1)))
	var left, right []byte
	result, _ := hex.DecodeString(v.EntryUUID)
	for i, h := range v.Hashes {
		if i < inner && (v.Index>>uint(i))&1 == 0 {
			left = result
			right, _ = hex.DecodeString(h)
		} else {
			left, _ = hex.DecodeString(h)
			right = result
		}
		result = hasher.HashChildren(left, right)
		s += fmt.Sprintf("SHA256(0x01 | %v | %v) =\n\t%v\n\n",
			hex.EncodeToString(left), hex.EncodeToString(right), hex.EncodeToString(result))
	}
	return s
}

// verifyCmd represents the get command
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Rekor verify command",
	Long:  `Verifies an entry exists in the transparency log through an inclusion proof`,
	PreRun: func(cmd *cobra.Command, args []string) {
		// these are bound here so that they are not overwritten by other commands
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.Logger.Fatal("Error initializing cmd line args: ", err)
		}
		if err := validateArtifactPFlags(true, true); err != nil {
			log.Logger.Error(err)
			_ = cmd.Help()
			os.Exit(1)
		}
	},
	Run: format.WrapCmd(func(args []string) (interface{}, error) {
		rekorClient, err := GetRekorClient(viper.GetString("rekor_server"))
		if err != nil {
			return nil, err
		}

		params := entries.NewGetLogEntryProofParams()
		params.EntryUUID = viper.GetString("uuid")
		if params.EntryUUID == "" {
			// without the UUID, we need to search for it
			searchParams := entries.NewSearchLogQueryParams()
			searchLogQuery := models.SearchLogQuery{}

			logIndex := viper.GetString("log-index")
			if logIndex != "" {
				logIndexInt, err := strconv.ParseInt(logIndex, 10, 0)
				if err != nil {
					return nil, fmt.Errorf("error parsing --log-index: %w", err)
				}
				searchLogQuery.LogIndexes = []*int64{&logIndexInt}
			} else {
				rekordEntry, err := CreateRekordFromPFlags()
				if err != nil {
					return nil, err
				}

				entries := []models.ProposedEntry{rekordEntry}
				searchLogQuery.SetEntries(entries)
			}
			searchParams.SetEntry(&searchLogQuery)

			resp, err := rekorClient.Entries.SearchLogQuery(searchParams)
			if err != nil {
				return nil, err
			}

			if len(resp.Payload) == 0 {
				return nil, fmt.Errorf("entry in log cannot be located")
			} else if len(resp.Payload) > 1 {
				return nil, fmt.Errorf("multiple entries returned; this should not happen")
			}
			logEntry := resp.Payload[0]
			if len(logEntry) != 1 {
				return nil, errors.New("UUID value can not be extracted")
			}
			for k := range logEntry {
				params.EntryUUID = k
			}
		}

		resp, err := rekorClient.Entries.GetLogEntryProof(params)
		if err != nil {
			return nil, err
		}

		o := &verifyCmdOutput{
			RootHash:  *resp.Payload.RootHash,
			EntryUUID: params.EntryUUID,
			Index:     *resp.Payload.LogIndex,
			Size:      *resp.Payload.TreeSize,
			Hashes:    resp.Payload.Hashes,
		}

		hashes := [][]byte{}
		for _, h := range resp.Payload.Hashes {
			hb, _ := hex.DecodeString(h)
			hashes = append(hashes, hb)
		}

		rootHash, _ := hex.DecodeString(*resp.Payload.RootHash)
		leafHash, _ := hex.DecodeString(params.EntryUUID)

		v := merkle.NewLogVerifier(rfc6962.DefaultHasher)
		if err := v.VerifyInclusionProof(*resp.Payload.LogIndex, *resp.Payload.TreeSize,
			hashes, rootHash, leafHash); err != nil {
			return nil, err
		}
		return o, err
	}),
}

func init() {
	if err := addArtifactPFlags(verifyCmd); err != nil {
		log.Logger.Fatal("Error parsing cmd line args:", err)
	}
	if err := addUUIDPFlags(verifyCmd, false); err != nil {
		log.Logger.Fatal("Error parsing cmd line args:", err)
	}
	if err := addLogIndexFlag(verifyCmd, false); err != nil {
		log.Logger.Fatal("Error parsing cmd line args:", err)
	}

	rootCmd.AddCommand(verifyCmd)
}
