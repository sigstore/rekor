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
	"fmt"
	"net/http"
	"time"

	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/projectrekor/rekor/pkg/log"
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
	client *TrillianClient
	pubkey *keyspb.PublicKey
}

func NewAPI(ctx context.Context) (*API, error) {
	logRPCServer := fmt.Sprintf("%s:%d",
		viper.GetString("trillian_log_server.address"),
		viper.GetUint("trillian_log_server.port"))
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

	return &API{
		client: TrillianClientInstance(logClient, tLogID, ctx),
		pubkey: t.PublicKey,
	}, nil
}

type ctxKeyRekorAPI int

const rekorAPILookupKey ctxKeyRekorAPI = 0

func AddAPIToContext(ctx context.Context) (context.Context, error) {
	api, err := NewAPI(ctx)
	if err != nil {
		return nil, err
	}
	return context.WithValue(ctx, rekorAPILookupKey, api), nil
}

func apiFromRequest(r *http.Request) *API {
	return r.Context().Value(rekorAPILookupKey).(*API)
}
