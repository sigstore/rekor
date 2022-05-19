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

package api

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/trillian"
	radix "github.com/mediocregopher/radix/v4"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/signer"
	"github.com/sigstore/rekor/pkg/storage"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

func dial(ctx context.Context, rpcServer string) (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Set up and test connection to rpc server
	creds := insecure.NewCredentials()
	conn, err := grpc.DialContext(ctx, rpcServer, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Logger.Fatalf("Failed to connect to RPC server:", err)
	}
	return conn, nil
}

type API struct {
	logClient  trillian.TrillianLogClient
	logID      int64
	logRanges  sharding.LogRanges
	pubkey     string // PEM encoded public key
	pubkeyHash string // SHA256 hash of DER-encoded public key
	signer     signature.Signer
}

func NewAPI(treeID uint) (*API, error) {
	logRPCServer := fmt.Sprintf("%s:%d",
		viper.GetString("trillian_log_server.address"),
		viper.GetUint("trillian_log_server.port"))
	ctx := context.Background()
	tConn, err := dial(ctx, logRPCServer)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	logAdminClient := trillian.NewTrillianAdminClient(tConn)
	logClient := trillian.NewTrillianLogClient(tConn)

	shardingConfig := viper.GetString("trillian_log_server.sharding_config")
	ranges, err := sharding.NewLogRanges(ctx, logClient, shardingConfig, treeID)
	if err != nil {
		return nil, fmt.Errorf("unable get sharding details from sharding config: %w", err)
	}

	tid := int64(treeID)
	if tid == 0 {
		log.Logger.Info("No tree ID specified, attempting to create a new tree")
		t, err := createAndInitTree(ctx, logAdminClient, logClient)
		if err != nil {
			return nil, fmt.Errorf("create and init tree: %w", err)
		}
		tid = t.TreeId
	}
	log.Logger.Infof("Starting Rekor server with active tree %v", tid)
	ranges.SetActive(tid)

	rekorSigner, err := signer.New(ctx, viper.GetString("rekor_server.signer"))
	if err != nil {
		return nil, fmt.Errorf("getting new signer: %w", err)
	}
	pk, err := rekorSigner.PublicKey(options.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("getting public key: %w", err)
	}
	b, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return nil, fmt.Errorf("marshalling public key: %w", err)
	}
	pubkeyHashBytes := sha256.Sum256(b)

	pubkey := cryptoutils.PEMEncode(cryptoutils.PublicKeyPEMType, b)

	return &API{
		// Transparency Log Stuff
		logClient: logClient,
		logID:     tid,
		logRanges: ranges,
		// Signing/verifying fields
		pubkey:     string(pubkey),
		pubkeyHash: hex.EncodeToString(pubkeyHashBytes[:]),
		signer:     rekorSigner,
	}, nil
}

var (
	api           *API
	redisClient   radix.Client
	storageClient storage.AttestationStorage
)

func ConfigureAPI(treeID uint) {
	cfg := radix.PoolConfig{}
	var err error

	api, err = NewAPI(treeID)
	if err != nil {
		log.Logger.Panic(err)
	}
	if viper.GetBool("enable_retrieve_api") {
		redisClient, err = cfg.New(context.Background(), "tcp", fmt.Sprintf("%v:%v", viper.GetString("redis_server.address"), viper.GetUint64("redis_server.port")))
		if err != nil {
			log.Logger.Panic("failure connecting to redis instance: ", err)
		}
	}

	if viper.GetBool("enable_attestation_storage") {
		storageClient, err = storage.NewAttestationStorage()
		if err != nil {
			log.Logger.Panic(err)
		}
	}
}
