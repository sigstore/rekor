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
package cmd

import (
	"io/ioutil"

	"github.com/projectrekor/rekor-cli/app"
	"github.com/projectrekor/rekor-cli/log"
	"github.com/spf13/viper"

	"github.com/spf13/cobra"
)

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Rekor get command",
	Long: `Performs a proof verification that a file

exists within the transparency log`,
	Run: func(cmd *cobra.Command, args []string) {
		log := log.Logger
		rekorServer := viper.GetString("rekor_server")
		url := rekorServer + "/api/v1/getproof"
		rekord := viper.GetString("rekord")

		rekorEntry, err := ioutil.ReadFile(rekord)
		if err != nil {
			log.Fatal(err)
		}
		app.DoGet(url, rekorEntry)
	},
}

func init() {
	rootCmd.AddCommand(getCmd)
}
