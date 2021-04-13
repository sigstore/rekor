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

package api

import (
	"context"
	"crypto"
	"fmt"
	"time"

	"github.com/google/trillian"
	"github.com/google/trillian/client"
	radix "github.com/mediocregopher/radix/v4"
	"github.com/pkg/errors"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/signer"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
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
	logClient trillian.TrillianLogClient
	logID     int64
	pubkey    crypto.PublicKey
	signer    signature.Signer
	verifier  *client.LogVerifier
}

func NewAPI() (*API, error) {
	logRPCServer := fmt.Sprintf("%s:%d",
		viper.GetString("trillian_log_server.address"),
		viper.GetUint("trillian_log_server.port"))
	ctx := context.Background()
	tConn, err := dial(ctx, logRPCServer)
	if err != nil {
		return nil, err
	}
	logAdminClient := trillian.NewTrillianAdminClient(tConn)
	logClient := trillian.NewTrillianLogClient(tConn)

	tLogID := viper.GetInt64("trillian_log_server.tlog_id")
	if tLogID == 0 {
		t, err := createAndInitTree(ctx, logAdminClient, logClient)
		if err != nil {
			return nil, err
		}
		tLogID = t.TreeId
	}

	t, err := logAdminClient.GetTree(ctx, &trillian.GetTreeRequest{
		TreeId: tLogID,
	})
	if err != nil {
		return nil, err
	}

	signer, err := signer.New(ctx, viper.GetString("rekor_server.signer"))
	if err != nil {
		return nil, errors.Wrap(err, "getting new signer")
	}
	pubkey, err := signer.PublicKey(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "getting public key")
	}

	verifier, err := client.NewLogVerifierFromTree(t)
	if err != nil {
		return nil, err
	}

	return &API{
		logClient: logClient,
		logID:     tLogID,
		pubkey:    pubkey,
		signer:    signer,
		verifier:  verifier,
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
