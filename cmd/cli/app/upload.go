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
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/google/trillian"
	"github.com/projectrekor/rekor/pkg/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type RespStatusCode struct {
	Code string `json:"file_received"`
}

type getLeafResponse struct {
	Status RespStatusCode
	Leaf   *trillian.GetLeavesByIndexResponse
	Key    []byte
}

// uploadCmd represents the upload command
var uploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Upload an artifact to Rekor",
	PreRun: func(cmd *cobra.Command, args []string) {
		// these are bound here so that they are not overwritten by other commands
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.Logger.Fatal("Error initializing cmd line args: ", err)
		}
		if err := validateRekorServerURL(); err != nil {
			log.Logger.Error(err)
			_ = cmd.Help()
			os.Exit(1)
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
		rekorServerURL := viper.GetString("rekor_server") + "/api/v1/add"

		rekorEntry, err := buildRekorEntryFromPFlags()
		if err != nil {
			log.Fatal(err)
		}

		marshalledRekorEntry, err := json.Marshal(*rekorEntry)
		if err != nil {
			log.Fatal("Error generating rekorfile: ", err)
		}

		// Upload to the rekor service
		log.Info("Uploading manifest to Rekor...")
		ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
		defer cancel()

		request, err := http.NewRequestWithContext(ctx, "POST", rekorServerURL, nil)
		if err != nil {
			log.Fatal(err)
		}

		request.Body = ioutil.NopCloser(bytes.NewReader(marshalledRekorEntry))
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

		leafresp := getLeafResponse{}

		if err := json.Unmarshal(content, &leafresp); err != nil {
			log.Fatal(err)
		}

		log.Info("Status: ", leafresp.Status)

		if leafresp.Status.Code != "OK" {
			os.Exit(1)
		}
	},
}

func init() {
	if err := addArtifactPFlags(uploadCmd); err != nil {
		log.Logger.Fatal("Error parsing cmd line args:", err)
	}

	rootCmd.AddCommand(uploadCmd)
}
