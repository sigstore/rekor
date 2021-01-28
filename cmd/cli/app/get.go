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
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/projectrekor/rekor/cmd/cli/app/format"
	"github.com/projectrekor/rekor/pkg/generated/client/entries"
	"github.com/projectrekor/rekor/pkg/generated/models"
	"github.com/projectrekor/rekor/pkg/log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type getCmdOutput struct {
	Body           []byte
	LogIndex       int
	IntegratedTime int64
}

func (g *getCmdOutput) String() string {
	s := fmt.Sprintf("Index: %d\n", g.LogIndex)
	dt := time.Unix(g.IntegratedTime, 0).UTC().Format(time.RFC3339)
	s += fmt.Sprintf("IntegratedTime: %s\n", dt)
	s += fmt.Sprintf("Body: %s\n", g.Body)
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
			log.Logger.Fatal("Error initializing cmd line args: ", err)
		}
	},
	Run: format.WrapCmd(func(args []string) (interface{}, error) {
		rekorClient, err := GetRekorClient(viper.GetString("rekor_server"))
		if err != nil {
			return nil, err
		}

		logIndex := viper.GetString("log-index")
		if logIndex != "" {
			params := entries.NewGetLogEntryByIndexParams()
			logIndexInt, err := strconv.ParseInt(logIndex, 10, 0)
			if err != nil {
				return nil, fmt.Errorf("error parsing --log-index: %w", err)
			}
			params.LogIndex = logIndexInt

			resp, err := rekorClient.Entries.GetLogEntryByIndex(params)
			if err != nil {
				return nil, err
			}
			for _, entry := range resp.Payload {
				return parseEntry(entry)
			}
		}

		uuid := viper.GetString("uuid")
		if uuid != "" {
			params := entries.NewGetLogEntryByUUIDParams()
			params.EntryUUID = uuid

			resp, err := rekorClient.Entries.GetLogEntryByUUID(params)
			if err != nil {
				return nil, err
			}

			for k, entry := range resp.Payload {
				if k != uuid {
					continue
				}
				return parseEntry(entry)
			}
		}

		return nil, errors.New("either --uuid or --log-index must be specified")
	}),
}

func parseEntry(e models.LogEntryAnon) (interface{}, error) {
	bytes, err := e.MarshalBinary()
	if err != nil {
		return nil, err
	}
	// Now parse that back into JSON in the format "body, logindex"
	obj := getCmdOutput{}
	if err := json.Unmarshal(bytes, &obj); err != nil {
		return nil, err
	}
	obj.IntegratedTime = e.IntegratedTime

	return &obj, nil
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
