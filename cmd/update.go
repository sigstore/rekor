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
	"os"
	"path/filepath"
	"time"

	"github.com/mitchellh/go-homedir"

	tcrypto "github.com/google/trillian/crypto"
	"go.uber.org/zap"

	tclient "github.com/google/trillian/client"

	"github.com/google/trillian"
	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/projectrekor/rekor-cli/log"
	"github.com/spf13/viper"

	"github.com/spf13/cobra"
)

type latestResponse struct {
	Proof *trillian.GetLatestSignedLogRootResponse
	Key   []byte
}

type state struct {
	Size int64
	Hash []byte
}

func stateDir() (string, error) {
	home, err := homedir.Dir()
	if err != nil {
		return "", err
	}
	rekorDir := filepath.Join(home, ".rekor")
	if _, err := os.Stat(rekorDir); os.IsNotExist(err) {
		if err := os.Mkdir(rekorDir, 0755); err != nil {
			return "", err
		}
	}
	return filepath.Join(home, ".rekor", "rekor.json"), nil
}

func getPreviousState(log *zap.SugaredLogger) *state {
	p, err := stateDir()
	if err != nil {
		return nil
	}
	var oldState state
	f, err := ioutil.ReadFile(p)
	if err != nil {
		log.Info(err)
		return nil
	}
	if err := json.Unmarshal(f, &oldState); err != nil {
		log.Info(err)
		return nil
	}
	return &oldState
}

func setState(size int64, hash []byte) error {
	// Update the file
	newState := state{
		Size: size,
		Hash: hash,
	}
	b, err := json.Marshal(newState)
	if err != nil {
		return err
	}
	p, err := stateDir()
	if err != nil {
		return nil
	}
	if err := ioutil.WriteFile(p, b, 0644); err != nil {
		return err
	}
	return nil
}

// updateCmd represents the get command
var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Rekor update command",
	Long:  `Performs a consistency proof against the tree between the last seen time and now`,
	Run: func(cmd *cobra.Command, args []string) {
		log := log.Logger
		rekorServer := viper.GetString("rekor_server")
		u := rekorServer + "/api/v1/latest"

		oldState := getPreviousState(log)

		// Set Context with Timeout for connects to thde log rpc server
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		request, err := http.NewRequestWithContext(ctx, "POST", u, nil)
		if err != nil {
			log.Fatal(err)
		}

		if oldState != nil {
			request.URL.RawQuery += fmt.Sprintf("lastSize=%d", oldState.Size)
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

		resp := latestResponse{}
		if err := json.Unmarshal(content, &resp); err != nil {
			log.Fatal(err)
		}

		pub, err := x509.ParsePKIXPublicKey(resp.Key)
		if err != nil {
			log.Fatal(err)
		}

		verifier := tclient.NewLogVerifier(rfc6962.DefaultHasher, pub, crypto.SHA256)
		root, err := tcrypto.VerifySignedLogRoot(verifier.PubKey, verifier.SigHash, resp.Proof.SignedLogRoot)
		if err != nil {
			log.Fatal(err)
		}

		newSize := int64(root.TreeSize)
		if oldState != nil && newSize <= oldState.Size {
			log.Infof("Tree is unchanged at size %d", newSize)
			return
		}
		// Only do the check if we sent an old one.
		if oldState != nil {
			v := merkle.NewLogVerifier(rfc6962.DefaultHasher)
			if err := v.VerifyConsistencyProof(oldState.Size, newSize, oldState.Hash, root.RootHash, resp.Proof.Proof.Hashes); err != nil {
				log.Fatal(err)
			}
			log.Infof("proof correct between sizes %d and %d", oldState.Size, newSize)
		}
		if err := setState(newSize, root.RootHash); err != nil {
			log.Fatal(err)
		}
		log.Info("State updated")
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
}
