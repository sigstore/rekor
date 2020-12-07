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
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/google/trillian"
	tclient "github.com/google/trillian/client"
	tcrypto "github.com/google/trillian/crypto"
	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/projectrekor/rekor/pkg/log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type getProofResponse struct {
	Status   string
	LeafHash string
	Proof    *trillian.GetInclusionProofByHashResponse
	Key      []byte
}

// verifyCmd represents the get command
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Rekor verify command",
	Long:  `Verifies an entry exists in the transparency log through an inclusion proof`,
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
	Run: func(cmd *cobra.Command, args []string) {
		log := log.Logger
		rekorServerURL := viper.GetString("rekor_server") + "/api/v1/getproof"

		rekorEntry, err := buildRekorEntryFromPFlags()
		if err != nil {
			log.Fatal(err)
		}

		// Now we have the RekorEntry, send it to the server!
		b, err := json.Marshal(rekorEntry.RekorLeaf)
		if err != nil {
			log.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		request, err := http.NewRequestWithContext(ctx, "POST", rekorServerURL, nil)
		if err != nil {
			log.Fatal(err)
		}

		request.Body = ioutil.NopCloser(bytes.NewReader(b))

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

		if resp.Proof != nil {
			leafHash, _ := hex.DecodeString(resp.LeafHash)
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
	if err := addArtifactPFlags(verifyCmd); err != nil {
		log.Logger.Fatal("Error parsing cmd line args:", err)
	}

	rootCmd.AddCommand(verifyCmd)
}
