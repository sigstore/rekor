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

	"github.com/projectrekor/rekor/pkg"
	"github.com/projectrekor/rekor/pkg/log"
	"github.com/projectrekor/rekor/pkg/types"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// verifyCmd represents the get command
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Rekor verify command",
	Long:  `Verifies a signature and checks that it exists in the transparency log`,
	Run: func(cmd *cobra.Command, args []string) {
		log := log.Logger
		rekorServer := viper.GetString("rekor_server")
		url := rekorServer + "/api/v1/getproof"

		// Figure out if the artifact is local or a URL
		isLocal := true
		if _, err := os.Stat(artifact); os.IsNotExist(err) {
			isLocal = false
		}

		// Signature and Public Key are always required
		sig, err := ioutil.ReadFile(signature)
		if err != nil {
			log.Fatal(err)
		}
		pubKey, err := ioutil.ReadFile(pk)
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
			body, err = ioutil.ReadFile(artifact)
			if err != nil {
				log.Fatal(err)
			}
			rekorEntry.Data = body
		} else {
			rekorEntry.URL = artifact
			rekorEntry.SHA = sha
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
	signature string
	artifact  string
	pk        string
	sha       string
)

func init() {
	log := log.Logger
	verifyCmd.Flags().StringVar(&signature, "signature", "", "path to signature file")
	if err := verifyCmd.MarkFlagFilename("signature"); err != nil {
		log.Fatal("Error parsing cmd line args:", err)
	}
	verifyCmd.Flags().StringVar(&artifact, "artifact", "", "path or URL to artifact file")
	verifyCmd.Flags().StringVar(&pk, "public-key", "", "path to public key file")
	if err := verifyCmd.MarkFlagFilename("public-key"); err != nil {
		log.Fatal("Error parsing cmd line args:", err)
	}
	verifyCmd.Flags().StringVar(&sha, "sha", "", "the sha of the contents")
	rootCmd.AddCommand(verifyCmd)
}
