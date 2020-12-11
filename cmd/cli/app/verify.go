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
	"os"

	"github.com/google/trillian/merkle"
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
		if err := validateArtifactPFlags(); err != nil {
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

			rekordEntry, err := CreateRekordFromPFlags()
			if err != nil {
				log.Fatal(err)
			}

			entries := []models.ProposedEntry{rekordEntry}
			searchLogQuery.SetEntries(entries)
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

		inclusionProof := resp.GetPayload()
		hashes := [][]byte{}

		for _, hash := range inclusionProof.Hashes {
			val, err := hex.DecodeString(hash)
			if err != nil {
				log.Fatal(err)
			}
			hashes = append(hashes, val)
		}

		leafHash, err := hex.DecodeString(params.EntryUUID)
		if err != nil {
			log.Fatal(err)
		}
		rootHash, err := hex.DecodeString(*inclusionProof.RootHash)
		if err != nil {
			log.Fatal(err)
		}

		v := merkle.NewLogVerifier(rfc6962.DefaultHasher)
		if err := v.VerifyInclusionProof(*inclusionProof.LogIndex, *inclusionProof.TreeSize, hashes, rootHash, leafHash); err != nil {
			log.Fatal(err)
		}
		log.Info("Proof correct!")
	},
}

func init() {
	if err := addArtifactPFlags(verifyCmd); err != nil {
		log.Logger.Fatal("Error parsing cmd line args:", err)
	}
	if err := addUUIDPFlags(verifyCmd, false); err != nil {
		log.Logger.Fatal("Error parsing cmd line args:", err)
	}

	rootCmd.AddCommand(verifyCmd)
}
