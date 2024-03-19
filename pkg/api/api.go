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
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/trillian"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"golang.org/x/exp/slices"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/rekor/pkg/indexstorage"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pubsub"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/signer"
	"github.com/sigstore/rekor/pkg/storage"
	"github.com/sigstore/rekor/pkg/trillianclient"
	"github.com/sigstore/rekor/pkg/witness"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"

	_ "github.com/sigstore/rekor/pkg/pubsub/gcp" // Load GCP pubsub implementation
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
	// stops checkpoint publishing
	checkpointPublishCancel context.CancelFunc
	// Publishes notifications when new entries are added to the log. May be
	// nil if no publisher is configured.
	newEntryPublisher pubsub.Publisher
	algorithmRegistry *signature.AlgorithmRegistryConfig
}

var AllowedClientSigningAlgorithms = []v1.PublicKeyDetails{
	v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256,
	v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_3072_SHA256,
	v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_4096_SHA256,
	v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
	v1.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384,
	v1.PublicKeyDetails_PKIX_ECDSA_P521_SHA_512,
	v1.PublicKeyDetails_PKIX_ED25519,
	v1.PublicKeyDetails_PKIX_ED25519_PH,
}
var DefaultClientSigningAlgorithms = AllowedClientSigningAlgorithms

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
		t, err := trillianclient.CreateAndInitTree(ctx, logAdminClient, logClient)
		if err != nil {
			return nil, fmt.Errorf("create and init tree: %w", err)
		}
		tid = t.TreeId
	}
	log.Logger.Infof("Starting Rekor server with active tree %v", tid)
	ranges.SetActive(tid)

	algorithmsOption := viper.GetStringSlice("client-signing-algorithms")
	var algorithms []v1.PublicKeyDetails
	if algorithmsOption == nil {
		algorithms = DefaultClientSigningAlgorithms
	} else {
		for _, a := range algorithmsOption {
			algorithm, err := signature.ParseSignatureAlgorithmFlag(a)
			if err != nil {
				return nil, fmt.Errorf("parsing signature algorithm flag: %w", err)
			}
			algorithms = append(algorithms, algorithm)
		}
	}
	algorithmsStr := make([]string, len(algorithms))
	for i, a := range algorithms {
		algorithmsStr[i], err = signature.FormatSignatureAlgorithmFlag(a)
		if err != nil {
			return nil, fmt.Errorf("formatting signature algorithm flag: %w", err)
		}
	}
	algorithmRegistry, err := signature.NewAlgorithmRegistryConfig(algorithms)
	if err != nil {
		return nil, fmt.Errorf("getting algorithm registry: %w", err)
	}
	log.Logger.Infof("Allowed client signing algorithms: %v", algorithmsStr)

	rekorSigner, err := signer.New(ctx, viper.GetString("rekor_server.signer"),
		viper.GetString("rekor_server.signer-passwd"))
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

	var newEntryPublisher pubsub.Publisher
	if p := viper.GetString("rekor_server.new_entry_publisher"); p != "" {
		if !viper.GetBool("rekor_server.publish_events_protobuf") && !viper.GetBool("rekor_server.publish_events_json") {
			return nil, fmt.Errorf("%q is configured but neither %q or %q are enabled", "new_entry_publisher", "publish_events_protobuf", "publish_events_json")
		}
		newEntryPublisher, err = pubsub.Get(ctx, p)
		if err != nil {
			return nil, fmt.Errorf("init event publisher: %w", err)
		}
		log.ContextLogger(ctx).Infof("Initialized new entry event publisher: %s", p)
	}

	return &API{
		// Transparency Log Stuff
		logClient: logClient,
		logID:     tid,
		logRanges: ranges,
		// Signing/verifying fields
		pubkey:     string(pubkey),
		pubkeyHash: hex.EncodeToString(pubkeyHashBytes[:]),
		signer:     rekorSigner,
		// Utility functionality not required for operation of the core service
		newEntryPublisher: newEntryPublisher,
		algorithmRegistry: algorithmRegistry,
	}, nil
}

var (
	api                      *API
	attestationStorageClient storage.AttestationStorage
	indexStorageClient       indexstorage.IndexStorage
	redisClient              *redis.Client
)

func ConfigureAPI(treeID uint) {
	var err error

	api, err = NewAPI(treeID)
	if err != nil {
		log.Logger.Panic(err)
	}
	if viper.GetBool("enable_retrieve_api") || viper.GetBool("enable_stable_checkpoint") ||
		slices.Contains(viper.GetStringSlice("enabled_api_endpoints"), "searchIndex") {
		indexStorageClient, err = indexstorage.NewIndexStorage(viper.GetString("search_index.storage_provider"))
		if err != nil {
			log.Logger.Panic(err)
		}
	}

	if viper.GetBool("enable_attestation_storage") {
		attestationStorageClient, err = storage.NewAttestationStorage()
		if err != nil {
			log.Logger.Panic(err)
		}
	}

	if viper.GetBool("enable_stable_checkpoint") {
		redisClient = NewRedisClient()
		checkpointPublisher := witness.NewCheckpointPublisher(context.Background(), api.logClient, api.logRanges.ActiveTreeID(),
			viper.GetString("rekor_server.hostname"), api.signer, redisClient, viper.GetUint("publish_frequency"), CheckpointPublishCount)

		// create context to cancel goroutine on server shutdown
		ctx, cancel := context.WithCancel(context.Background())
		api.checkpointPublishCancel = cancel
		checkpointPublisher.StartPublisher(ctx)
	}
}

func NewRedisClient() *redis.Client {

	opts := &redis.Options{
		Addr:     fmt.Sprintf("%v:%v", viper.GetString("redis_server.address"), viper.GetUint64("redis_server.port")),
		Password: viper.GetString("redis_server.password"),
		Network:  "tcp",
		DB:       0, // default DB
	}

	// #nosec G402
	if viper.GetBool("redis_server.enable-tls") {
		opts.TLSConfig = &tls.Config{
			InsecureSkipVerify: viper.GetBool("redis_server.insecure-skip-verify"), //nolint: gosec
		}
	}

	return redis.NewClient(opts)
}

func StopAPI() {
	api.checkpointPublishCancel()

	if api.newEntryPublisher != nil {
		if err := api.newEntryPublisher.Close(); err != nil {
			log.Logger.Errorf("shutting down newEntryPublisher: %v", err)
		}
	}

	if indexStorageClient != nil {
		if err := indexStorageClient.Shutdown(); err != nil {
			log.Logger.Errorf("shutting down indexStorageClient: %v", err)
		}
	}
}
