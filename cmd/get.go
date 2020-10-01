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
	"crypto"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	tcrypto "github.com/google/trillian/crypto"

	tclient "github.com/google/trillian/client"

	"github.com/google/trillian"
	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/projectrekor/rekor-cli/log"
	"github.com/spf13/viper"

	"github.com/spf13/cobra"
)

type getProofResponse struct {
	Status string
	Proof  *trillian.GetInclusionProofByHashResponse
	Key    []byte
}

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
		linkfile := viper.GetString("linkfile")

		// Set Context with Timeout for connects to thde log rpc server
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		request, err := http.NewRequestWithContext(ctx, "POST", url, nil)
		if err != nil {
			log.Fatal(err)
		}

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

		resp := getProofResponse{}
		if err := json.Unmarshal(content, &resp); err != nil {
			log.Fatal(err)
		}

		pub, err := x509.ParsePKIXPublicKey(resp.Key)
		if err != nil {
			log.Fatal(err)
		}

		f, err := ioutil.ReadFile(linkfile)
		if err != nil {
			log.Fatal(err)
		}

		if resp.Proof != nil {
			leafHash := rfc6962.DefaultHasher.HashLeaf(f)
			verifier := tclient.NewLogVerifier(rfc6962.DefaultHasher, pub, crypto.SHA256)
			root, err := tcrypto.VerifySignedLogRoot(verifier.PubKey, verifier.SigHash, resp.Proof.SignedLogRoot)
			if err != nil {
				log.Fatal(err)
			}

			v := merkle.NewLogVerifier(rfc6962.DefaultHasher)
			proof := resp.Proof.Proof[0]
			if err := v.VerifyInclusionProof(proof.LeafIndex, int64(root.TreeSize), proof.Hashes, root.RootHash, leafHash); err != nil {
				log.Fatal(err)
			}
			log.Info("Proof correct!")
		} else {
			log.Info(resp.Status)
		}
	},
}

func init() {
	rootCmd.AddCommand(getCmd)
}
