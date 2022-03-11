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
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/trillian"
	radix "github.com/mediocregopher/radix/v4"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/sigstore/rekor/pkg/log"
	pki "github.com/sigstore/rekor/pkg/pki/x509"
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
	logClient    trillian.TrillianLogClient
	logID        int64
	logRanges    sharding.LogRanges
	pubkey       string // PEM encoded public key
	pubkeyHash   string // SHA256 hash of DER-encoded public key
	signer       signature.Signer
	tsaSigner    signature.Signer    // the signer to use for timestamping
	certChain    []*x509.Certificate // timestamping cert chain
	certChainPem string              // PEM encoded timestamping cert chain
}

func NewAPI(ranges sharding.LogRanges) (*API, error) {
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
		log.Logger.Info("No tree ID specified, attempting to intitialize one")
		t, err := createAndInitTree(ctx, logAdminClient, logClient)
		if err != nil {
			return nil, errors.Wrap(err, "create and init tree")
		}
		tLogID = t.TreeId
	}
	// append the active treeID to the API's logRangeMap for lookups
	ranges.AppendRange(sharding.LogRange{TreeID: tLogID})

	rekorSigner, err := signer.New(ctx, viper.GetString("rekor_server.signer"))
	if err != nil {
		return nil, errors.Wrap(err, "getting new signer")
	}
	pk, err := rekorSigner.PublicKey(options.WithContext(ctx))
	if err != nil {
		return nil, errors.Wrap(err, "getting public key")
	}
	b, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling public key")
	}
	pubkeyHashBytes := sha256.Sum256(b)

	pubkey := cryptoutils.PEMEncode(cryptoutils.PublicKeyPEMType, b)

	// Use an in-memory key for timestamping
	tsaSigner, err := signer.New(ctx, signer.MemoryScheme)
	if err != nil {
		return nil, errors.Wrap(err, "getting new tsa signer")
	}
	tsaPk, err := tsaSigner.PublicKey(options.WithContext(ctx))
	if err != nil {
		return nil, errors.Wrap(err, "getting public key")
	}

	var certChain []*x509.Certificate
	b64CertChainStr := viper.GetString("rekor_server.timestamp_chain")
	if b64CertChainStr != "" {
		certChainStr, err := base64.StdEncoding.DecodeString(b64CertChainStr)
		if err != nil {
			return nil, errors.Wrap(err, "decoding timestamping cert")
		}
		if certChain, err = pki.ParseTimestampCertChain([]byte(certChainStr)); err != nil {
			return nil, errors.Wrap(err, "parsing timestamp cert chain")
		}
	}

	// Generate a tsa certificate from the rekor signer and provided certificate chain
	certChain, err = signer.NewTimestampingCertWithChain(ctx, tsaPk, rekorSigner, certChain)
	if err != nil {
		return nil, errors.Wrap(err, "generating timestamping cert chain")
	}
	certChainPem, err := pki.CertChainToPEM(certChain)
	if err != nil {
		return nil, errors.Wrap(err, "timestamping cert chain")
	}

	return &API{
		// Transparency Log Stuff
		logClient: logClient,
		logID:     tLogID,
		logRanges: ranges,
		// Signing/verifying fields
		pubkey:     string(pubkey),
		pubkeyHash: hex.EncodeToString(pubkeyHashBytes[:]),
		signer:     rekorSigner,
		// TSA signing stuff
		tsaSigner:    tsaSigner,
		certChain:    certChain,
		certChainPem: string(certChainPem),
	}, nil
}

var (
	api           *API
	redisClient   radix.Client
	storageClient storage.AttestationStorage
)

func ConfigureAPI(ranges sharding.LogRanges) {
	cfg := radix.PoolConfig{}
	var err error

	api, err = NewAPI(ranges)
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
