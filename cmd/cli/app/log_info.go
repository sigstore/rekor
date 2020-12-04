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
	"net/url"

	"github.com/projectrekor/rekor/pkg/generated/client"
	"github.com/projectrekor/rekor/pkg/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// verifyCmd represents the get command
var logInfoCmd = &cobra.Command{
	Use:   "loginfo",
	Short: "Rekor loginfo command",
	Long:  `Prints info about the transparency log`,
	Run: func(cmd *cobra.Command, args []string) {
		log := log.Logger
		rekorServer := viper.GetString("rekor_server")

		url, err := url.Parse(rekorServer)
		if err != nil {
			log.Fatal(err)
		}

		tc := client.DefaultTransportConfig().WithHost(url.Host)
		rc := client.NewHTTPClientWithConfig(nil, tc)

		result, err := rc.Tlog.GetLogInfo(nil)
		if err != nil {
			log.Fatal(err)
		}

		logInfo := result.GetPayload()
		fmt.Printf("Tree Size: %v, Root Hash: %v\n", *logInfo.TreeSize, *logInfo.RootHash)
	},
}

func init() {
	rootCmd.AddCommand(logInfoCmd)
}
