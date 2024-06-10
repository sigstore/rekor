// Copyright 2024 The Sigstore Authors.
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

/*
	backfill-index is a script to populate the index storage database with
	entries from Rekor. This is sometimes necessary because caching is
	best effort. If Redis returns an error, the database will not, and so sometimes
	we need to backfill missing entries into the database for the search API.
	It can also be used to populate an index storage backend from scratch.

	To run:
	go run cmd/backfill-index/main.go --rekor-address <address> \
	    --hostname <redis-hostname> --port <redis-port> --concurrency <num-of-workers> \
		--start <first index to backfill> --end <last index to backfill> [--dry-run]
*/

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-openapi/runtime"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/errgroup"
	"sigs.k8s.io/release-utils/version"

	"github.com/sigstore/rekor/pkg/client"
	rekorclient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"

	// these imports are to call the packages' init methods
	_ "github.com/sigstore/rekor/pkg/types/alpine/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/cose/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/dsse/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/helm/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/intoto/v0.0.2"
	_ "github.com/sigstore/rekor/pkg/types/jar/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/rfc3161/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/rpm/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/tuf/v0.0.1"
)

const (
	mysqlWriteStmt       = "INSERT IGNORE INTO EntryIndex (EntryKey, EntryUUID) VALUES (:key, :uuid)"
	mysqlCreateTableStmt = `CREATE TABLE IF NOT EXISTS EntryIndex (
		PK BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		EntryKey varchar(512) NOT NULL,
		EntryUUID char(80) NOT NULL,
		PRIMARY KEY(PK),
		UNIQUE(EntryKey, EntryUUID)
	)`
)

type provider int

const (
	providerUnset provider = iota
	providerRedis
	providerMySQL
)

type indexClient interface {
	idempotentAddToIndex(ctx context.Context, key, value string) error
}

type redisClient struct {
	client *redis.Client
}

type mysqlClient struct {
	client *sqlx.DB
}

var (
	redisHostname           = flag.String("redis-hostname", "", "Hostname for Redis application")
	redisPort               = flag.String("redis-port", "", "Port to Redis application")
	redisPassword           = flag.String("redis-password", "", "Password for Redis authentication")
	redisEnableTLS          = flag.Bool("redis-enable-tls", false, "Enable TLS for Redis client")
	redisInsecureSkipVerify = flag.Bool("redis-insecure-skip-verify", false, "Whether to skip TLS verification for Redis client or not")
	mysqlDSN                = flag.String("mysql-dsn", "", "MySQL Data Source Name")
	startIndex              = flag.Int("start", -1, "First index to backfill")
	endIndex                = flag.Int("end", -1, "Last index to backfill")
	rekorAddress            = flag.String("rekor-address", "", "Address for Rekor, e.g. https://rekor.sigstore.dev")
	rekorDisableKeepalives  = flag.Bool("rekor-disable-keepalives", true, "Disable Keep-Alive connections (defaults to true, meaning Keep-Alive is disabled)")
	rekorRetryCount         = flag.Uint("rekor-retry-count", 3, "Maximum number of times to retry rekor requests")                          // https://github.com/sigstore/rekor/blob/5988bfa6b0761be3a810047d23b3d3191ed5af3d/pkg/client/options.go#L36
	rekorRetryWaitMin       = flag.Duration("rekor-retry-wait-min", 1*time.Second, "Minimum time to wait between retrying rekor requests")  //nolint:revive // https://github.com/hashicorp/go-retryablehttp/blob/1542b31176d3973a6ecbc06c05a2d0df89b59afb/client.go#L49
	rekorRetryWaitMax       = flag.Duration("rekor-retry-wait-max", 30*time.Second, "Maximum time to wait between retrying rekor requests") // https://github.com/hashicorp/go-retryablehttp/blob/1542b31176d3973a6ecbc06c05a2d0df89b59afb/client.go#L50
	versionFlag             = flag.Bool("version", false, "Print the current version of Backfill MySQL")
	concurrency             = flag.Int("concurrency", 1, "Number of workers to use for backfill")
	dryRun                  = flag.Bool("dry-run", false, "Dry run - don't actually insert into MySQL")
)

func main() {
	flag.Parse()

	versionInfo := version.GetVersionInfo()
	if *versionFlag {
		fmt.Println(versionInfo.String())
		os.Exit(0)
	}

	provider := providerUnset
	if *mysqlDSN != "" && *redisHostname != "" {
		log.Fatal("Ambiguous backend address: either mysql-dsn or redis-hostname must be set, but not both")
	}
	if *mysqlDSN != "" {
		provider = providerMySQL
	}
	if *redisHostname != "" || *redisPort != "" || *redisPassword != "" {
		provider = providerRedis
	}
	if provider == providerUnset {
		log.Fatal("Must set mysql-dsn for MySQL or redis-hostname and redis-port for Redis")
	}
	if provider == providerRedis {
		if *redisHostname == "" {
			log.Fatal("Redis address must be set")
		}
		if *redisPort == "" {
			log.Fatal("Redis port must be set")
		}
	}
	if *startIndex == -1 {
		log.Fatal("start must be set to >=0")
	}
	if *endIndex == -1 {
		log.Fatal("end must be set to >=0")
	}
	if *rekorAddress == "" {
		log.Fatal("rekor-address must be set")
	}

	log.Printf("running backfill index Version: %s GitCommit: %s BuildDate: %s", versionInfo.GitVersion, versionInfo.GitCommit, versionInfo.BuildDate)

	indexClient, err := getIndexClient(provider)
	if err != nil {
		log.Fatalf("creating index client: %v", err)
	}

	opts := []client.Option{client.WithNoDisableKeepalives(!*rekorDisableKeepalives)}
	opts = append(opts, client.WithRetryCount(*rekorRetryCount))
	opts = append(opts, client.WithRetryWaitMin(*rekorRetryWaitMin))
	opts = append(opts, client.WithRetryWaitMax(*rekorRetryWaitMax))
	rekorClient, err := client.GetRekorClient(*rekorAddress, opts...)
	if err != nil {
		log.Fatalf("creating rekor client: %v", err)
	}

	err = populate(indexClient, rekorClient)
	if err != nil {
		log.Fatalf("populating index: %v", err)
	}
}

// getIndexClient creates a client for the provided index backend.
func getIndexClient(backend provider) (indexClient, error) {
	switch backend {
	case providerRedis:
		opts := &redis.Options{
			Addr:     fmt.Sprintf("%s:%s", *redisHostname, *redisPort),
			Password: *redisPassword,
			Network:  "tcp",
			DB:       0, // default DB
		}
		// #nosec G402
		if *redisEnableTLS {
			opts.TLSConfig = &tls.Config{
				InsecureSkipVerify: *redisInsecureSkipVerify, //nolint: gosec
			}
		}
		return &redisClient{client: redis.NewClient(opts)}, nil
	case providerMySQL:
		dbClient, err := sqlx.Open("mysql", *mysqlDSN)
		if err != nil {
			return nil, err
		}
		if err = dbClient.Ping(); err != nil {
			return nil, err
		}
		if _, err = dbClient.Exec(mysqlCreateTableStmt); err != nil {
			return nil, err
		}
		return &mysqlClient{client: dbClient}, nil
	default:
		return nil, fmt.Errorf("could not create client for unexpected provider")
	}
}

// populate does the heavy lifting of populating the index storage for whichever client is passed in.
func populate(indexClient indexClient, rekorClient *rekorclient.Rekor) error {
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	group, ctx := errgroup.WithContext(ctx)
	group.SetLimit(*concurrency)

	type result struct {
		index      int
		parseErrs  []error
		insertErrs []error
	}
	var resultChan = make(chan result)
	parseErrs := make([]int, 0)
	insertErrs := make([]int, 0)

	go func() {
		for r := range resultChan {
			if len(r.parseErrs) > 0 {
				parseErrs = append(parseErrs, r.index)
			}
			if len(r.insertErrs) > 0 {
				insertErrs = append(insertErrs, r.index)
			}
		}
	}()

	for i := *startIndex; i <= *endIndex; i++ {
		index := i // capture loop variable for closure
		group.Go(func() error {
			params := entries.NewGetLogEntryByIndexParamsWithContext(ctx)
			params.SetLogIndex(int64(index))
			resp, err := rekorClient.Entries.GetLogEntryByIndex(params)
			if err != nil {
				// in case of sigterm, just return to exit gracefully
				if errors.Is(err, context.Canceled) {
					return nil
				}
				log.Fatalf("retrieving log uuid by index: %v", err)
			}
			var parseErrs []error
			var insertErrs []error
			for uuid, entry := range resp.Payload {
				// uuid is the global UUID - tree ID and entry UUID
				e, _, _, err := unmarshalEntryImpl(entry.Body.(string))
				if err != nil {
					parseErrs = append(parseErrs, fmt.Errorf("error unmarshalling entry for %s: %w", uuid, err))
					continue
				}
				keys, err := e.IndexKeys()
				if err != nil {
					parseErrs = append(parseErrs, fmt.Errorf("error building index keys for %s: %w", uuid, err))
					continue
				}
				for _, key := range keys {
					if err := indexClient.idempotentAddToIndex(ctx, key, uuid); err != nil {
						insertErrs = append(insertErrs, fmt.Errorf("error inserting UUID %s with key %s: %w", uuid, key, err))
					}
					fmt.Printf("Uploaded entry %s, index %d, key %s\n", uuid, index, key)
				}
			}
			if len(insertErrs) != 0 || len(parseErrs) != 0 {
				fmt.Printf("Errors with log index %d:\n", index)
				for _, e := range insertErrs {
					fmt.Println(e)
				}
				for _, e := range parseErrs {
					fmt.Println(e)
				}
			} else {
				fmt.Printf("Completed log index %d\n", index)
			}
			resultChan <- result{
				index:      index,
				parseErrs:  parseErrs,
				insertErrs: insertErrs,
			}

			return nil
		})
	}
	err := group.Wait()
	if err != nil {
		log.Fatalf("error running backfill: %v", err)
	}
	close(resultChan)
	fmt.Println("Backfill complete")
	if len(parseErrs) > 0 {
		return fmt.Errorf("failed to parse %d entries: %v", len(parseErrs), parseErrs)
	}
	if len(insertErrs) > 0 {
		return fmt.Errorf("failed to insert/remove %d entries: %v", len(insertErrs), insertErrs)
	}
	return nil
}

// unmarshalEntryImpl decodes the base64-encoded entry to a specific entry type (types.EntryImpl).
// Taken from Cosign
func unmarshalEntryImpl(e string) (types.EntryImpl, string, string, error) {
	b, err := base64.StdEncoding.DecodeString(e)
	if err != nil {
		return nil, "", "", err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
	if err != nil {
		return nil, "", "", err
	}

	entry, err := types.UnmarshalEntry(pe)
	if err != nil {
		return nil, "", "", err
	}
	return entry, pe.Kind(), entry.APIVersion(), nil
}

func (c *redisClient) idempotentAddToIndex(ctx context.Context, key, value string) error {
	if *dryRun {
		return nil
	}
	// remove the key-value pair from the index in case it already exists
	_, err := c.client.LRem(ctx, key, 0, value).Result()
	if err != nil {
		return err
	}
	_, err = c.client.LPush(ctx, key, value).Result()
	return err
}

func (c *mysqlClient) idempotentAddToIndex(ctx context.Context, key, value string) error {
	if *dryRun {
		return nil
	}
	_, err := c.client.NamedExecContext(ctx, mysqlWriteStmt, map[string]any{"key": key, "uuid": value})
	return err
}
