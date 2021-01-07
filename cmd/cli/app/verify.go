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
	"fmt"
	"math/bits"
	"os"
	"strconv"

	"github.com/google/trillian/merkle/rfc6962"
	"github.com/projectrekor/rekor/pkg/generated/client/entries"
	"github.com/projectrekor/rekor/pkg/generated/models"
	"github.com/projectrekor/rekor/pkg/log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

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
	Run: func(cmd *cobra.Command, args []string) {
		log := log.Logger
		rekorClient, err := GetRekorClient(viper.GetString("rekor_server"))
		if err != nil {
			log.Fatal(err)
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
					log.Fatal(fmt.Errorf("error parsing --log-index: %w", err))
				}
				searchLogQuery.LogIndexes = []*int64{&logIndexInt}
			} else {
				rekordEntry, err := CreateRekordFromPFlags()
				if err != nil {
					log.Fatal(err)
				}

				entries := []models.ProposedEntry{rekordEntry}
				searchLogQuery.SetEntries(entries)
			}
			searchParams.SetEntry(&searchLogQuery)

			resp, err := rekorClient.Entries.SearchLogQuery(searchParams)
			if err != nil {
				log.Fatal(err)
			}

			if len(resp.Payload) == 0 {
				log.Fatal(fmt.Errorf("entry in log cannot be located"))
			} else if len(resp.Payload) > 1 {
				log.Fatal(fmt.Errorf("multiple entries returned; this should not happen"))
			}
			logEntry := resp.Payload[0]
			if len(logEntry) != 1 {
				log.Fatal("UUID value can not be extracted")
			}
			for k := range logEntry {
				params.EntryUUID = k
			}
		}

		resp, err := rekorClient.Entries.GetLogEntryProof(params)
		if err != nil {
			log.Fatal(err)
		}

		inclusionProof := resp.Payload
		index := *inclusionProof.LogIndex
		size := *inclusionProof.TreeSize
		rootHash := *inclusionProof.RootHash
		fmt.Printf("Current Root Hash: %v\n", rootHash)
		fmt.Printf("Entry Hash: %v\n", params.EntryUUID)
		fmt.Printf("Entry Index: %v\n", index)
		fmt.Printf("Current Tree Size: %v\n\n", size)

		hasher := rfc6962.DefaultHasher
		inner := bits.Len64(uint64(index ^ (size - 1)))
		var left, right []byte
		result, _ := hex.DecodeString(params.EntryUUID)
		fmt.Printf("Inclusion Proof:\n")
		for i, h := range inclusionProof.Hashes {
			if i < inner && (index>>uint(i))&1 == 0 {
				left = result
				right, _ = hex.DecodeString(h)
			} else {
				left, _ = hex.DecodeString(h)
				right = result
			}
			result = hasher.HashChildren(left, right)
			fmt.Printf("SHA256(0x01 | %v | %v) =\n\t%v\n\n", hex.EncodeToString(left), hex.EncodeToString(right), hex.EncodeToString(result))
		}
		resultHash := hex.EncodeToString(result)

		if resultHash == rootHash {
			fmt.Printf("%v == %v, proof complete\n", resultHash, rootHash)
		} else {
			fmt.Printf("proof could not be correctly generated!")
		}
	},
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
