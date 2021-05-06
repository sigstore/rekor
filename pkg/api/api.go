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
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/trillian"
	"github.com/google/trillian/client"
	radix "github.com/mediocregopher/radix/v4"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/signer"
	"github.com/sigstore/sigstore/pkg/signature"
)

func dial(ctx context.Context, rpcServer string) (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Set up and test connection to rpc server
	conn, err := grpc.DialContext(ctx, rpcServer, grpc.WithInsecure())
	if err != nil {
		log.Logger.Fatalf("Failed to connect to RPC server:", err)
	}
	return conn, nil
}

type API struct {
	logClient  trillian.TrillianLogClient
	logID      int64
	pubkey     string // PEM encoded public key
	pubkeyHash string // SHA256 hash of DER-encoded public key
	signer     signature.Signer
	verifier   *client.LogVerifier
}

func NewAPI() (*API, error) {
	logRPCServer := fmt.Sprintf("%s:%d",
		viper.GetString("trillian_log_server.address"),
		viper.GetUint("trillian_log_server.port"))
	ctx := context.Background()
	tConn, err := dial(ctx, logRPCServer)
	if err != nil {
		return nil, errors.Wrap(err, "dial")
	}
	logAdminClient := trillian.NewTrillianAdminClient(tConn)
	logClient := trillian.NewTrillianLogClient(tConn)

	tLogID := viper.GetInt64("trillian_log_server.tlog_id")
	if tLogID == 0 {
		t, err := createAndInitTree(ctx, logAdminClient, logClient)
		if err != nil {
			return nil, errors.Wrap(err, "create and init tree")
		}
		tLogID = t.TreeId
	}

	t, err := logAdminClient.GetTree(ctx, &trillian.GetTreeRequest{
		TreeId: tLogID,
	})
	if err != nil {
		return nil, errors.Wrap(err, "get tree")
	}

	signer, err := signer.New(ctx, viper.GetString("rekor_server.signer"))
	if err != nil {
		return nil, errors.Wrap(err, "getting new signer")
	}
	pk, err := signer.PublicKey(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "getting public key")
	}
	b, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling public key")
	}
	hasher := sha256.New()
	if _, err = hasher.Write(b); err != nil {
		return nil, errors.Wrap(err, "computing hash of public key")
	}
	pubkeyHashBytes := hasher.Sum(nil)

	pubkey := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	})

	verifier, err := client.NewLogVerifierFromTree(t)
	if err != nil {
		return nil, errors.Wrap(err, "new verifier")
	}

	return &API{
		logClient:  logClient,
		logID:      tLogID,
		pubkey:     string(pubkey),
		pubkeyHash: hex.EncodeToString(pubkeyHashBytes),
		signer:     signer,
		verifier:   verifier,
	}, nil
}

var (
	api         *API
	redisClient radix.Client
)

func ConfigureAPI() {
	cfg := radix.PoolConfig{}
	var err error
	api, err = NewAPI()
	if err != nil {
		log.Logger.Panic(err)
	}
	if viper.GetBool("enable_retrieve_api") {
		redisClient, err = cfg.New(context.Background(), "tcp", fmt.Sprintf("%v:%v", viper.GetString("redis_server.address"), viper.GetUint64("redis_server.port")))
		if err != nil {
			log.Logger.Panic(err)
		}
	}
}
