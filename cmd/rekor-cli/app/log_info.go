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
	"fmt"
	"time"

	"github.com/go-openapi/swag"
	"github.com/google/trillian/merkle/logverifier"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/pkg/errors"
	rclient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
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
	TreeID         string
}

func (l *logInfoCmdOutput) String() string {
	// Verification is always successful if we return an object.
	ts := time.Unix(0, int64(l.TimestampNanos)).UTC().Format(time.RFC3339)

	return fmt.Sprintf(`Verification Successful!
Tree Size: %v
Root Hash: %s
Timestamp: %s
TreeID:    %s
`, l.TreeSize, l.RootHash, ts, l.TreeID)
}

// logInfoCmd represents the current information about the transparency log
var logInfoCmd = &cobra.Command{
	Use:   "loginfo",
	Short: "Rekor loginfo command",
	Long:  `Prints info about the transparency log`,
	Run: format.WrapCmd(func(args []string) (interface{}, error) {
		serverURL := viper.GetString("rekor_server")
		rekorClient, err := client.GetRekorClient(serverURL, client.WithUserAgent(UserAgent()))
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

		// Verify inactive shards
		if err := verifyInactiveTrees(rekorClient, serverURL, logInfo.InactiveShards); err != nil {
			return nil, err
		}

		// Verify the active tree
		sth := util.SignedCheckpoint{}
		signedTreeHead := swag.StringValue(logInfo.SignedTreeHead)
		if err := sth.UnmarshalText([]byte(signedTreeHead)); err != nil {
			return nil, err
		}
		treeID := swag.StringValue(logInfo.TreeID)

		if err := verifyTree(rekorClient, signedTreeHead, serverURL, treeID); err != nil {
			return nil, err
		}

		cmdOutput := &logInfoCmdOutput{
			TreeSize:       swag.Int64Value(logInfo.TreeSize),
			RootHash:       swag.StringValue(logInfo.RootHash),
			TimestampNanos: sth.GetTimestamp(),
			TreeID:         swag.StringValue(logInfo.TreeID),
		}
		return cmdOutput, nil
	}),
}

func verifyInactiveTrees(rekorClient *rclient.Rekor, serverURL string, inactiveShards []*models.InactiveShardLogInfo) error {
	if inactiveShards == nil {
		return nil
	}
	log.CliLogger.Infof("Validating inactive shards...")
	for _, shard := range inactiveShards {
		signedTreeHead := swag.StringValue(shard.SignedTreeHead)
		treeID := swag.StringValue(shard.TreeID)
		if err := verifyTree(rekorClient, signedTreeHead, serverURL, treeID); err != nil {
			return errors.Wrapf(err, "verifying inactive shard with ID %s", treeID)
		}
	}
	log.CliLogger.Infof("Successfully validated inactive shards")
	return nil
}

func verifyTree(rekorClient *rclient.Rekor, signedTreeHead, serverURL, treeID string) error {
	oldState := state.Load(serverURL)
	if treeID != "" {
		oldState = state.Load(treeID)
	}
	sth := util.SignedCheckpoint{}
	if err := sth.UnmarshalText([]byte(signedTreeHead)); err != nil {
		return err
	}
	verifier, err := loadVerifier(rekorClient)
	if err != nil {
		return err
	}
	if !sth.Verify(verifier) {
		return errors.New("signature on tree head did not verify")
	}

	if err := proveConsistency(rekorClient, oldState, sth, treeID); err != nil {
		return err
	}

	if viper.GetBool("store_tree_state") {
		if treeID != "" {
			if err := state.Dump(treeID, &sth); err != nil {
				log.CliLogger.Infof("Unable to store previous state: %v", err)
			}
		}
		if err := state.Dump(serverURL, &sth); err != nil {
			log.CliLogger.Infof("Unable to store previous state: %v", err)
		}
	}
	return nil
}

func proveConsistency(rekorClient *rclient.Rekor, oldState *util.SignedCheckpoint, sth util.SignedCheckpoint, treeID string) error {
	if oldState == nil {
		log.CliLogger.Infof("No previous log state stored, unable to prove consistency")
		return nil
	}
	persistedSize := oldState.Size
	switch {
	case persistedSize < sth.Size:
		log.CliLogger.Infof("Found previous log state, proving consistency between %d and %d", oldState.Size, sth.Size)
		params := tlog.NewGetLogProofParams()
		firstSize := int64(persistedSize)
		params.FirstSize = &firstSize
		params.LastSize = int64(sth.Size)
		params.TreeID = &treeID
		proof, err := rekorClient.Tlog.GetLogProof(params)
		if err != nil {
			return err
		}
		hashes := [][]byte{}
		for _, h := range proof.Payload.Hashes {
			b, _ := hex.DecodeString(h)
			hashes = append(hashes, b)
		}
		v := logverifier.New(rfc6962.DefaultHasher)
		if err := v.VerifyConsistencyProof(firstSize, int64(sth.Size), oldState.Hash,
			sth.Hash, hashes); err != nil {
			return err
		}
		log.CliLogger.Infof("Consistency proof valid!")
	case persistedSize == sth.Size:
		if !bytes.Equal(oldState.Hash, sth.Hash) {
			return errors.New("root hash returned from server does not match previously persisted state")
		}
		log.CliLogger.Infof("Persisted log state matches the current state of the log")
	default:
		return fmt.Errorf("current size of tree reported from server %d is less than previously persisted state %d", sth.Size, persistedSize)
	}
	return nil
}

func loadVerifier(rekorClient *rclient.Rekor) (signature.Verifier, error) {
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

	return signature.LoadVerifier(pub, crypto.SHA256)
}

func init() {
	initializePFlagMap()
	rootCmd.AddCommand(logInfoCmd)
}
