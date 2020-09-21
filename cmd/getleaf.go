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
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/google/trillian"
	tclient "github.com/google/trillian/client"
	tcrypto "github.com/google/trillian/crypto"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/projectrekor/rekor-cli/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type getLeafResponse struct {
	Leaf *trillian.GetLeavesByIndexResponse
	Key  []byte
}

// type leafStruct struct {
// 	Leaf struct {
// 		Leaves []struct {
// 			MerkleLeafHash   string `json:"merkle_leaf_hash"`
// 			LeafValue        string `json:"leaf_value"`
// 			LeafIndex        int    `json:"leaf_index"`
// 			LeafIdentityHash string `json:"leaf_identity_hash"`
// 			QueueTimestamp   struct {
// 				Seconds int `json:"seconds"`
// 				Nanos   int `json:"nanos"`
// 			} `json:"queue_timestamp"`
// 			IntegrateTimestamp struct {
// 				Seconds int `json:"seconds"`
// 				Nanos   int `json:"nanos"`
// 			} `json:"integrate_timestamp"`
// 		} `json:"leaves"`
// 		SignedLogRoot struct {
// 			KeyHint          string `json:"key_hint"`
// 			LogRoot          string `json:"log_root"`
// 			LogRootSignature string `json:"log_root_signature"`
// 		} `json:"signed_log_root"`
// 	} `json:"Leaf"`
// 	Key string `json:"Key"`
// }

// getleafCmd represents the getleaf command
var getleafCmd = &cobra.Command{
	Use:   "getleaf",
	Short: "Rekor Get Leaf Command",
	Long:  `Get Leaf entry by Index`,
	Run: func(cmd *cobra.Command, args []string) {
		log := log.Logger
		rekorServer := viper.GetString("rekor_server")
		leafIndex := viper.GetString("leafIndex")
		u := rekorServer + "/api/v1/getleaf"

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		request, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			log.Fatal(err)
		}

		request.URL.RawQuery += fmt.Sprintf("leafindex=%s", leafIndex)

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

		resp := getLeafResponse{}
		if err := json.Unmarshal(content, &resp); err != nil {
			log.Fatal(err)
		}

		pub, err := x509.ParsePKIXPublicKey(resp.Key)
		if err != nil {
			log.Fatal(err)
		}

		verifier := tclient.NewLogVerifier(rfc6962.DefaultHasher, pub, crypto.SHA256)
		root, err := tcrypto.VerifySignedLogRoot(verifier.PubKey, verifier.SigHash, resp.Leaf.SignedLogRoot)

		if err != nil {
			log.Fatal(err)
		}

		log.Info("Leaf content", resp.Leaf.Leaves)
		log.Info("Root: ", root.TreeSize)
	},
}

func init() {
	rootCmd.AddCommand(getleafCmd)
	getleafCmd.PersistentFlags().String("index", "", "Leaf Index")
	viper.BindPFlag("linkfile", getleafCmd.PersistentFlags().Lookup("index"))
}
