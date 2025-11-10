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
	"crypto/tls"
	"fmt"
	"slices"

	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/rekor/pkg/indexstorage"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pubsub"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/signer"
	"github.com/sigstore/rekor/pkg/storage"
	"github.com/sigstore/rekor/pkg/trillianclient"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore/pkg/signature"

	_ "github.com/sigstore/rekor/pkg/pubsub/gcp" // Load GCP pubsub implementation
)

type API struct {
	trillianClientManager *trillianclient.ClientManager
	logRanges             *sharding.LogRanges
	// Publishes notifications when new entries are added to the log. May be
	// nil if no publisher is configured.
	newEntryPublisher pubsub.Publisher
	algorithmRegistry *signature.AlgorithmRegistryConfig
	// Stores map of inactive tree IDs to checkpoints
	// Inactive shards will always return the same checkpoint,
	// so we can fetch the checkpoint on service startup to
	// minimize signature generations
	cachedCheckpoints map[int64]string
}

func (api *API) ActiveTreeID() int64 {
	return api.logRanges.GetActive().TreeID
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

func NewAPI(treeID int64) (*API, error) {
	ctx := context.Background()

	// this is also used for the active tree
	defaultGRPCConfig := trillianclient.GRPCConfig{
		Address:             viper.GetString("trillian_log_server.address"),
		Port:                viper.GetUint16("trillian_log_server.port"),
		TLSCACert:           viper.GetString("trillian_log_server.tls_ca_cert"),
		UseSystemTrustStore: viper.GetBool("trillian_log_server.tls"),
		GRPCServiceConfig:   viper.GetString("trillian_log_server.grpc_default_service_config"),
	}

	if treeID == 0 {
		log.Logger.Info("No tree ID specified, attempting to create a new tree")
		t, err := trillianclient.CreateAndInitTree(ctx, defaultGRPCConfig)
		if err != nil {
			return nil, fmt.Errorf("create and init tree: %w", err)
		}
		treeID = t.TreeId
	}

	shardingConfig := viper.GetString("trillian_log_server.sharding_config")
	signingConfig := signer.SigningConfig{
		SigningSchemeOrKeyPath: viper.GetString("rekor_server.signer"),
		FileSignerPassword:     viper.GetString("rekor_server.signer-passwd"),
		TinkKEKURI:             viper.GetString("rekor_server.tink_kek_uri"),
		TinkKeysetPath:         viper.GetString("rekor_server.tink_keyset_path"),
		GCPKMSRetries:          viper.GetUint("rekor_server.signer.gcpkms.retries"),
		GCPKMSTimeout:          viper.GetUint("rekor_server.signer.gcpkms.timeout"),
	}
	ranges, err := sharding.NewLogRanges(ctx, shardingConfig, treeID, signingConfig)
	if err != nil {
		return nil, fmt.Errorf("unable get sharding details from sharding config: %w", err)
	}

	inactiveGRPCConfigs := make(map[int64]trillianclient.GRPCConfig)
	for _, r := range ranges.GetInactive() {
		if r.GRPCConfig != nil {
			inactiveGRPCConfigs[r.TreeID] = *r.GRPCConfig
		}
	}
	tcm := trillianclient.NewClientManager(inactiveGRPCConfigs, defaultGRPCConfig)

	roots, err := ranges.CompleteInitialization(ctx, tcm)
	if err != nil {
		return nil, fmt.Errorf("completing log ranges initialization: %w", err)
	}

	log.Logger.Infof("Starting Rekor server with active tree %v", treeID)

	algorithmsOption := viper.GetStringSlice("client-signing-algorithms")
	var algorithms []v1.PublicKeyDetails
	if len(algorithmsOption) == 0 {
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

	cachedCheckpoints := make(map[int64]string)
	for _, r := range ranges.GetInactive() {
		root, ok := roots[r.TreeID]
		if !ok {
			return nil, fmt.Errorf("no root found for inactive shard %d", r.TreeID)
		}
		treeLength, err := util.SafeInt64ToUint64(r.TreeLength)
		if err != nil {
			return nil, err
		}
		cp, err := util.CreateAndSignCheckpoint(ctx, viper.GetString("rekor_server.hostname"), r.TreeID, treeLength, root.RootHash, r.Signer)
		if err != nil {
			return nil, fmt.Errorf("error signing checkpoint for inactive shard %d: %w", r.TreeID, err)
		}
		cachedCheckpoints[r.TreeID] = string(cp)
	}

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
		trillianClientManager: tcm,
		logRanges:             ranges,
		// Utility functionality not required for operation of the core service
		newEntryPublisher: newEntryPublisher,
		algorithmRegistry: algorithmRegistry,
		cachedCheckpoints: cachedCheckpoints,
	}, nil
}

var (
	api                      *API
	attestationStorageClient storage.AttestationStorage
	indexStorageClient       indexstorage.IndexStorage
)

func ConfigureAPI(treeID int64) {
	var err error

	api, err = NewAPI(treeID)
	if err != nil {
		log.Logger.Panic(err)
	}
	if viper.GetBool("enable_retrieve_api") || slices.Contains(viper.GetStringSlice("enabled_api_endpoints"), "searchIndex") {
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

	if api.trillianClientManager != nil {
		if err := api.trillianClientManager.Close(); err != nil {
			log.Logger.Errorf("shutting down trillian client manager: %v", err)
		}
	}
}
