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
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/projectrekor/rekor/pkg"
	"github.com/projectrekor/rekor/pkg/log"
	"github.com/projectrekor/rekor/pkg/types"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Rekor verify command",
	Long:  `Verifies a signature and checks that it exists in the transparency log`,
	Run: func(cmd *cobra.Command, args []string) {
		log := log.Logger
		rekorServer := viper.GetString("rekor_server")
		url := rekorServer + "/api/v1/getproof"
		signature := viper.GetString("signature")
		publicKey := viper.GetString("public-key")
		artifactURL := viper.GetString("artifact-url")
		artifactPATH := viper.GetString("artifact-path")
		artifactSHA := viper.GetString("artifact-sha")

		// verify the artifact is local
		isLocal := true
		if _, err := os.Stat(artifactPATH); os.IsNotExist(err) {
			isLocal = false
		}

		// Signature and Public Key are always required
		sig, err := ioutil.ReadFile(filepath.Clean(signature))
		if err != nil {
			log.Fatal(err)
		}
		pubKey, err := ioutil.ReadFile(filepath.Clean(publicKey))
		if err != nil {
			log.Fatal(err)
		}

		rekorEntry := &types.RekorEntry{
			RekorLeaf: types.RekorLeaf{
				Signature: sig,
				PublicKey: pubKey,
			},
		}
		var body []byte
		if isLocal {
			var err error
			body, err = ioutil.ReadFile(filepath.Clean(artifactPATH))
			if err != nil {
				log.Fatal(err)
			}
			rekorEntry.Data = body
		} else {
			rekorEntry.URL = artifactURL
			rekorEntry.SHA = artifactSHA
		}
		if err := rekorEntry.Load(context.Background()); err != nil {
			log.Fatal(err)
		}

		// Now we have the RekorEntry, send it to the server!
		b, err := json.Marshal(rekorEntry)
		if err != nil {
			log.Fatal(err)
		}
		pkg.DoGet(url, b)
	},
}

var (
	signature    string
	artifactURL  string
	artifactPATH string
	publicKey    string
	artifactSHA  string
)

func init() {
	rootCmd.AddCommand(verifyCmd)
}
