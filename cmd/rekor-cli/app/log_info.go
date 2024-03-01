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
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/go-openapi/swag"
	rclient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"

	"github.com/sigstore/rekor/pkg/verify"
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
	ActiveTreeSize int64
	TotalTreeSize  int64
	RootHash       string
	TreeID         string
}

func (l *logInfoCmdOutput) String() string {
	// Verification is always successful if we return an object.
	return fmt.Sprintf(`Verification Successful!
Active Tree Size:       %v
Total Tree Size:        %v
Root Hash:              %s
TreeID:                 %s
`, l.ActiveTreeSize, l.TotalTreeSize, l.RootHash, l.TreeID)
}

// logInfoCmd represents the current information about the transparency log
var logInfoCmd = &cobra.Command{
	Use:   "loginfo",
	Short: "Rekor loginfo command",
	Long:  `Prints info about the transparency log`,
	Run: format.WrapCmd(func(_ []string) (interface{}, error) {
		serverURL := viper.GetString("rekor_server")
		ctx := context.Background()
		rekorClient, err := client.GetRekorClient(serverURL, client.WithUserAgent(UserAgent()), client.WithRetryCount(viper.GetUint("retry")), client.WithLogger(log.CliLogger))
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
		if err := verifyInactiveTrees(ctx, rekorClient, serverURL, logInfo.InactiveShards); err != nil {
			return nil, err
		}

		// Verify the active tree
		sth := util.SignedCheckpoint{}
		signedTreeHead := swag.StringValue(logInfo.SignedTreeHead)
		if err := sth.UnmarshalText([]byte(signedTreeHead)); err != nil {
			return nil, err
		}
		treeID := swag.StringValue(logInfo.TreeID)

		if err := verifyTree(ctx, rekorClient, signedTreeHead, serverURL, treeID); err != nil {
			return nil, err
		}

		cmdOutput := &logInfoCmdOutput{
			ActiveTreeSize: swag.Int64Value(logInfo.TreeSize),
			TotalTreeSize:  totalTreeSize(logInfo, logInfo.InactiveShards),
			RootHash:       swag.StringValue(logInfo.RootHash),
			TreeID:         swag.StringValue(logInfo.TreeID),
		}
		return cmdOutput, nil
	}),
}

func verifyInactiveTrees(ctx context.Context, rekorClient *rclient.Rekor, serverURL string, inactiveShards []*models.InactiveShardLogInfo) error {
	if inactiveShards == nil {
		return nil
	}
	log.CliLogger.Infof("Validating inactive shards...")
	for _, shard := range inactiveShards {
		signedTreeHead := swag.StringValue(shard.SignedTreeHead)
		treeID := swag.StringValue(shard.TreeID)
		if err := verifyTree(ctx, rekorClient, signedTreeHead, serverURL, treeID); err != nil {
			return fmt.Errorf("verifying inactive shard with ID %s: %w", treeID, err)
		}
	}
	log.CliLogger.Infof("Successfully validated inactive shards")
	return nil
}

func verifyTree(ctx context.Context, rekorClient *rclient.Rekor, signedTreeHead, serverURL, treeID string) error {
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

	if oldState != nil {
		if err := verify.ProveConsistency(ctx, rekorClient, oldState, &sth, treeID); err != nil {
			return err
		}
	} else {
		log.CliLogger.Infof("No previous log state stored, unable to prove consistency")
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

func totalTreeSize(activeShard *models.LogInfo, inactiveShards []*models.InactiveShardLogInfo) int64 {
	total := swag.Int64Value(activeShard.TreeSize)
	for _, i := range inactiveShards {
		total += swag.Int64Value(i.TreeSize)
	}
	return total
}

func init() {
	initializePFlagMap()
	rootCmd.AddCommand(logInfoCmd)
}
