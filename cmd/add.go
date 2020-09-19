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
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/projectrekor/rekor-cli/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

//type LeafData struct {
//	File string `json:"file"`
//	Hash string `json:"hash"`
//}

//type LeafData struct {
//	Signatures []struct {
//		Keyid string `json:"keyid"`
//		Sig   string `json:"sig"`
//	} `json:"signatures"`
//	Signed struct {
//		Type       string `json:"_type"`
//		Byproducts struct {
//			ReturnValue int    `json:"return-value"`
//			Stderr      string `json:"stderr"`
//			Stdout      string `json:"stdout"`
//		} `json:"byproducts"`
//		Command     []string `json:"command"`
//		Environment struct {
//		} `json:"environment"`
//		Materials struct {
//			FooPy struct {
//				Sha256 string `json:"sha256"`
//			} `json:"foo.py"`
//		} `json:"materials"`
//		Name     string `json:"name"`
//		Products struct {
//			FooTarGz struct {
//				Sha256 string `json:"sha256"`
//			} `json:"foo.tar.gz"`
//		} `json:"products"`
//	} `json:"signed"`
//}

// addCmd represents the add command
var addCmd = &cobra.Command{
	Use:   "add",
	Short: "Rekor Add Command",
	Long: `Add a linkfile to rekor

The Add command will send a link file to rekor which will 
then hash the file into the transparency log`,

	Run: func(cmd *cobra.Command, args []string) {
		log := log.Logger
		rekorServer := viper.GetString("rekor_server")
		url := rekorServer + "/api/v1/add"
		linkfile := viper.GetString("linkfile")

		// Set Context with Timeout for connects to thde log rpc server
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		request, err := http.NewRequestWithContext(ctx, "POST", url, nil)

		if err := addFileToRequest(request, linkfile); err != nil {
			log.Fatal(err)
		}
		client := &http.Client{}
		response, err := client.Do(request)

		if err != nil {
			log.Fatal(err)
		}
		defer response.Body.Close()

		content, err := ioutil.ReadAll(response.Body)

		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(content))
	},
}

func init() {
	rootCmd.AddCommand(addCmd)
}
