/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

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

// rekor upload --signature=acme.sig --public-key=acme.pub --artifact=https://acmeproject/acme123.tar.gz | ./acme123.tar.gz --sha
package cmd

import (
	"github.com/projectrekor/rekor-cli/log"
	"github.com/spf13/cobra"
)

// uploadCmd represents the upload command
var uploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Upload a rekord to rekor",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		log := log.Logger
		log.Info("Upload Called")
		// rekorServer := viper.GetString("rekor_server")
		// url := rekorServer + "/api/v1/upload"
	},
}

func init() {
	rootCmd.AddCommand(uploadCmd)
}
