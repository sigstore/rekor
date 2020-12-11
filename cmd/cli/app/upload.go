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
	"os"

	"github.com/projectrekor/rekor/pkg/generated/client/entries"
	"github.com/projectrekor/rekor/pkg/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// uploadCmd represents the upload command
var uploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Upload an artifact to Rekor",
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
	Long: `This command takes the public key, signature and URL of the release artifact and uploads it to the rekor server.`,
	Run: func(cmd *cobra.Command, args []string) {
		log := log.Logger
		rekorClient, err := GetRekorClient(viper.GetString("rekor_server"))
		if err != nil {
			log.Fatal(err)
		}
		params := entries.NewCreateLogEntryParams()

		rekordEntry, err := CreateRekordFromPFlags()
		if err != nil {
			log.Fatal(err)
		}
		params.SetProposedEntry(rekordEntry)

		resp, err := rekorClient.Entries.CreateLogEntry(params)
		if err != nil {
			log.Fatal(err)
		}

		log.Info("Created entry at: ", resp.Location)
	},
}

func init() {
	if err := addArtifactPFlags(uploadCmd); err != nil {
		log.Logger.Fatal("Error parsing cmd line args:", err)
	}

	rootCmd.AddCommand(uploadCmd)
}
