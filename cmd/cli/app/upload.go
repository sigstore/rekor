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
	"path/filepath"
	"time"

	"github.com/google/trillian"
	"github.com/projectrekor/rekor/pkg/log"
	"github.com/projectrekor/rekor/pkg/types"
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
	Short: "Upload a rekord file",
	Long: `This command takes the public key, signature and URL
of the release artifact and uploads it to the rekor server.`,
	PreRun: func(cmd *cobra.Command, args []string) {
		// these are bound here so that they are not overwritten by other commands
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.Logger.Fatal("Error initializing cmd line args: ", err)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		log := log.Logger
		rekorServerURL := viper.GetString("rekor_server") + "/api/v1/add"
		signature := viper.GetString("signature")
		publicKey := viper.GetString("public-key")
		artifactURL := viper.GetString("artifact-url")

		// Before we download anything or validate the signing
		// Let's check the formatting is correct, if not we
		// exit and allow the user to resolve their corrupted
		// GPG files.

		var rekorEntry types.RekorEntry
		rekorEntry.URL = artifactURL

		var err error
		rekorEntry.Signature, err = ioutil.ReadFile(filepath.Clean(signature))
		if err != nil {
			log.Fatal("Error reading signature file: ", err)
		}

		rekorEntry.PublicKey, err = ioutil.ReadFile(filepath.Clean(publicKey))
		if err != nil {
			log.Fatal("Error reading public key: ", err)
		}

		if err := (&(rekorEntry.RekorLeaf)).ValidateLeaf(); err != nil {
			log.Fatal("Error validating signature/key: ", err)
		}

		// Download the artifact set within flag artifactURL
		log.Info("Downloading artifact..")
		ctx := context.Background()
		if err := rekorEntry.Load(ctx); err != nil {
			log.Fatal("Error processing artifact: ", err)
		}

		marshalledRekorEntry, err := json.Marshal(rekorEntry)
		if err != nil {
			log.Fatal("Error generating rekorfile: ", err)
		}

		// Upload to the rekor service
		log.Info("Uploading manifest to Rekor...")
		ctx, cancel := context.WithTimeout(ctx, 180*time.Second)
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
	},
}

func init() {
	rootCmd.AddCommand(uploadCmd)
}
