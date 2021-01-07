/*
Copyright © 2020 Bob Callaway <bcallawa@redhat.com>

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
	"fmt"
	"strconv"

	"github.com/projectrekor/rekor/pkg/generated/client/entries"
	"github.com/projectrekor/rekor/pkg/log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Rekor get command",
	Long:  `Get information regarding entries in the transparency log`,
	PreRun: func(cmd *cobra.Command, args []string) {
		// these are bound here so that they are not overwritten by other commands
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.Logger.Fatal("Error initializing cmd line args: ", err)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		log := log.Logger
		rekorClient, err := GetRekorClient(viper.GetString("rekor_server"))
		if err != nil {
			log.Fatal(err)
		}

		logIndex := viper.GetString("log-index")
		if logIndex != "" {
			params := entries.NewGetLogEntryByIndexParams()
			logIndexInt, err := strconv.ParseInt(logIndex, 10, 0)
			if err != nil {
				log.Fatal(fmt.Errorf("error parsing --log-index: %w", err))
			}
			params.LogIndex = logIndexInt

			resp, err := rekorClient.Entries.GetLogEntryByIndex(params)
			if err != nil {
				log.Fatal(err)
			}

			for _, entry := range resp.Payload {
				bytes, err := entry.MarshalBinary()
				if err != nil {
					log.Fatal(err)
				}
				log.Info(string(bytes))
			}
			return
		}

		uuid := viper.GetString("uuid")
		if uuid != "" {
			params := entries.NewGetLogEntryByUUIDParams()
			params.EntryUUID = uuid

			resp, err := rekorClient.Entries.GetLogEntryByUUID(params)
			if err != nil {
				log.Fatal(err)
			}

			for _, entry := range resp.Payload {
				bytes, err := entry.MarshalBinary()
				if err != nil {
					log.Fatal(err)
				}
				log.Info(string(bytes))
			}
			return
		}

		log.Fatal("either --uuid or --log-index must be specified")
	},
}

func init() {
	if err := addUUIDPFlags(getCmd, false); err != nil {
		log.Logger.Fatal("Error parsing cmd line args:", err)
	}
	if err := addLogIndexFlag(getCmd, false); err != nil {
		log.Logger.Fatal("Error parsing cmd line args:", err)
	}

	rootCmd.AddCommand(getCmd)
}
