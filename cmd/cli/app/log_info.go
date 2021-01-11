/*
Copyright © 2020 Bob Callaway <bcallawa@redhat.com>

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
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/google/trillian"
	tclient "github.com/google/trillian/client"
	tcrypto "github.com/google/trillian/crypto"
	"github.com/google/trillian/merkle/rfc6962"

	"github.com/projectrekor/rekor/pkg/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// logInfoCmd represents the current information about the transparency log
var logInfoCmd = &cobra.Command{
	Use:   "loginfo",
	Short: "Rekor loginfo command",
	Long:  `Prints info about the transparency log`,
	Run: func(cmd *cobra.Command, args []string) {
		log := log.Logger
		rekorClient, err := GetRekorClient(viper.GetString("rekor_server"))
		if err != nil {
			log.Fatal(err)
		}

		result, err := rekorClient.Tlog.GetLogInfo(nil)
		if err != nil {
			log.Fatal(err)
		}

		logInfo := result.GetPayload()
		fmt.Printf("Tree Size: %v, Root Hash: %v\n", *logInfo.TreeSize, *logInfo.RootHash)

		keyHint, err := base64.StdEncoding.DecodeString(logInfo.SignedTreeHead.KeyHint.String())
		if err != nil {
			log.Fatal(err)
		}
		logRoot, err := base64.StdEncoding.DecodeString(logInfo.SignedTreeHead.LogRoot.String())
		if err != nil {
			log.Fatal(err)
		}
		signature, err := base64.StdEncoding.DecodeString(logInfo.SignedTreeHead.Signature.String())
		if err != nil {
			log.Fatal(err)
		}
		sth := trillian.SignedLogRoot{
			KeyHint:          keyHint,
			LogRoot:          logRoot,
			LogRootSignature: signature,
		}

		publicKey := viper.GetString("rekor_server_public_key")
		if publicKey == "" {
			// fetch key from server
			keyResp, err := rekorClient.Tlog.GetPublicKey(nil)
			if err != nil {
				log.Fatal(err)
			}
			publicKey = keyResp.Payload
		}

		block, _ := pem.Decode([]byte(publicKey))
		if block == nil {
			log.Fatal("failed to decode public key of server")
			return
		}

		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}

		verifier := tclient.NewLogVerifier(rfc6962.DefaultHasher, pub, crypto.SHA256)
		if _, err := tcrypto.VerifySignedLogRoot(verifier.PubKey, verifier.SigHash, &sth); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Verified signature of log root!\n")
	},
}

func init() {
	rootCmd.AddCommand(logInfoCmd)
}
