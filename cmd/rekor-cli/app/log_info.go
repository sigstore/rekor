//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package app

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/google/trillian/merkle/logverifier"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/sigstore/rekor/cmd/rekor-cli/app/format"
	"github.com/sigstore/rekor/cmd/rekor-cli/app/state"
	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/tlog"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore/pkg/signature"
)

type logInfoCmdOutput struct {
	TreeSize       int64
	RootHash       string
	TimestampNanos uint64
}

func (l *logInfoCmdOutput) String() string {
	// Verification is always successful if we return an object.
	ts := time.Unix(0, int64(l.TimestampNanos)).UTC().Format(time.RFC3339)
	return fmt.Sprintf(`Verification Successful!
Tree Size: %v
Root Hash: %s
Timestamp: %s
`, l.TreeSize, l.RootHash, ts)
}

// logInfoCmd represents the current information about the transparency log
var logInfoCmd = &cobra.Command{
	Use:   "loginfo",
	Short: "Rekor loginfo command",
	Long:  `Prints info about the transparency log`,
	Run: format.WrapCmd(func(args []string) (interface{}, error) {
		serverURL := viper.GetString("rekor_server")
		rekorClient, err := client.GetRekorClient(serverURL)
		if err != nil {
			return nil, err
		}

		params := tlog.GetLogInfoParams{}
		params.SetTimeout(viper.GetDuration("timeout"))
		result, err := rekorClient.Tlog.GetLogInfo(&params)
		if err != nil {
			return nil, err
		}

		logInfo := result.GetPayload()

		sth := util.SignedCheckpoint{}
		if err := sth.UnmarshalText([]byte(*logInfo.SignedTreeHead)); err != nil {
			return nil, err
		}

		publicKey := viper.GetString("rekor_server_public_key")
		if publicKey == "" {
			// fetch key from server
			keyResp, err := rekorClient.Pubkey.GetPublicKey(nil)
			if err != nil {
				return nil, err
			}
			publicKey = keyResp.Payload
		}

		block, _ := pem.Decode([]byte(publicKey))
		if block == nil {
			return nil, errors.New("failed to decode public key of server")
		}

		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		verifier, err := signature.LoadVerifier(pub, crypto.SHA256)
		if err != nil {
			return nil, err
		}

		if !sth.Verify(verifier) {
			return nil, errors.New("signature on tree head did not verify")
		}

		cmdOutput := &logInfoCmdOutput{
			TreeSize:       *logInfo.TreeSize,
			RootHash:       *logInfo.RootHash,
			TimestampNanos: sth.GetTimestamp(),
		}

		oldState := state.Load(serverURL)
		if oldState != nil {
			persistedSize := oldState.Size
			if persistedSize < sth.Size {
				log.CliLogger.Infof("Found previous log state, proving consistency between %d and %d", oldState.Size, sth.Size)
				params := tlog.NewGetLogProofParams()
				firstSize := int64(persistedSize)
				params.FirstSize = &firstSize
				params.LastSize = int64(sth.Size)
				proof, err := rekorClient.Tlog.GetLogProof(params)
				if err != nil {
					return nil, err
				}
				hashes := [][]byte{}
				for _, h := range proof.Payload.Hashes {
					b, _ := hex.DecodeString(h)
					hashes = append(hashes, b)
				}
				v := logverifier.New(rfc6962.DefaultHasher)
				if err := v.VerifyConsistencyProof(firstSize, int64(sth.Size), oldState.Hash,
					sth.Hash, hashes); err != nil {
					return nil, err
				}
				log.CliLogger.Infof("Consistency proof valid!")
			} else if persistedSize == sth.Size {
				if !bytes.Equal(oldState.Hash, sth.Hash) {
					return nil, errors.New("root hash returned from server does not match previously persisted state")
				}
				log.CliLogger.Infof("Persisted log state matches the current state of the log")
			} else if persistedSize > sth.Size {
				return nil, fmt.Errorf("current size of tree reported from server %d is less than previously persisted state %d", sth.Size, persistedSize)
			}
		} else {
			log.CliLogger.Infof("No previous log state stored, unable to prove consistency")
		}

		if viper.GetBool("store_tree_state") {
			if err := state.Dump(serverURL, &sth); err != nil {
				log.CliLogger.Infof("Unable to store previous state: %v", err)
			}
		}
		return cmdOutput, nil
	}),
}

func init() {
	initializePFlagMap()
	rootCmd.AddCommand(logInfoCmd)
}
