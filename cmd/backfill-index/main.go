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

	The tool supports automatic checkpointing for both Redis and MySQL backends to allow
	resuming interrupted backfills and to maintain progress across scheduled runs.
	Use --checkpoint-interval to control how frequently checkpoints are saved
	(e.g., --checkpoint-interval 100 saves every 100 entries). On subsequent runs,
	the tool automatically continues from the last checkpoint unless --reset-checkpoint is set.
	Checkpoints persist indefinitely for scheduled jobs.

	To run:
	go run cmd/backfill-index/main.go --rekor-address <address> \
	    --redis-hostname <redis-hostname> --redis-port <redis-port> --concurrency <num-of-workers> \
		--start <first index to backfill> --end <last index to backfill> \
		[--checkpoint-interval <N>] [--reset-checkpoint] [--checkpoint-key <key>] [--dry-run]
*/

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
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
	mysqlCheckpointTableStmt = `CREATE TABLE IF NOT EXISTS BackfillCheckpoint (
		CheckpointKey VARCHAR(255) NOT NULL,
		LastCompletedIndex INT NOT NULL,
		LastUpdated TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		PRIMARY KEY(CheckpointKey)
	)`
	mysqlCheckpointSaveStmt   = `REPLACE INTO BackfillCheckpoint (CheckpointKey, LastCompletedIndex) VALUES (:key, :lastIndex)`
	mysqlCheckpointLoadStmt   = `SELECT LastCompletedIndex, LastUpdated FROM BackfillCheckpoint WHERE CheckpointKey = ?`
	mysqlCheckpointDeleteStmt = `DELETE FROM BackfillCheckpoint WHERE CheckpointKey = ?`
)

type provider int

const (
	providerUnset provider = iota
	providerRedis
	providerMySQL
)

type indexClient interface {
	idempotentAddToIndex(ctx context.Context, key, value string) error
	saveCheckpoint(ctx context.Context, checkpointKey string, state checkpointState) error
	loadCheckpoint(ctx context.Context, checkpointKey string) (*checkpointState, error)
	deleteCheckpoint(ctx context.Context, checkpointKey string) error
	supportsCheckpointing() bool
}

type redisClient struct {
	client *redis.Client
}

type mysqlClient struct {
	client *sqlx.DB
}

type checkpointState struct {
	LastCompletedIndex int       `json:"last_completed_index"`
	LastUpdated        time.Time `json:"last_updated"`
}

type checkpointUpdate struct {
	index int
}

type headers map[string][]string

func (h *headers) String() string {
	return fmt.Sprintf("%#v", h)
}

func (h *headers) Set(value string) error {
	parts := strings.Split(value, "=")
	k, v := parts[0], parts[1]
	if *h == nil {
		*h = make(map[string][]string)
	}
	if _, ok := (*h)[k]; !ok {
		(*h)[k] = make([]string, 0)
	}
	(*h)[k] = append((*h)[k], v)
	return nil
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
	rekorHeaders            headers
	versionFlag             = flag.Bool("version", false, "Print the current version of Backfill MySQL")
	concurrency             = flag.Int("concurrency", 1, "Number of workers to use for backfill")
	dryRun                  = flag.Bool("dry-run", false, "Dry run - don't actually insert into MySQL")
	checkpointInterval      = flag.Int("checkpoint-interval", 100, "Save checkpoint every N entries (0 to disable)")
	resetCheckpoint         = flag.Bool("reset-checkpoint", false, "Clear checkpoint and start from --start value")
	checkpointKey           = flag.String("checkpoint-key", "", "Custom Redis key for checkpoint (default: \"default\")")
)

func main() {
	flag.Var(&rekorHeaders, "rekor-header", "HTTP headers for Rekor in key=value format, repeat flag to add additional headers")
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
	if *checkpointInterval < 0 {
		log.Fatal("checkpoint-interval must be >= 0")
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
	opts = append(opts, client.WithHeaders(rekorHeaders))
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
		if _, err = dbClient.Exec(mysqlCheckpointTableStmt); err != nil {
			return nil, err
		}
		return &mysqlClient{client: dbClient}, nil
	default:
		return nil, fmt.Errorf("could not create client for unexpected provider")
	}
}

// populate does the heavy lifting of populating the index storage for whichever client is passed in.
func populate(indexClient indexClient, rekorClient *rekorclient.Rekor) (err error) {
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	group, ctx := errgroup.WithContext(ctx)
	group.SetLimit(*concurrency)

	var checkpointKeyName string
	var checkpointChan chan checkpointUpdate
	var checkpointDone chan struct{}
	var useCheckpointing = *checkpointInterval > 0 && indexClient.supportsCheckpointing()
	originalStartIndex := *startIndex

	if useCheckpointing {
		checkpointKeyName = *checkpointKey
		if checkpointKeyName == "" {
			checkpointKeyName = "default"
		}

		if *resetCheckpoint {
			if err := indexClient.deleteCheckpoint(ctx, checkpointKeyName); err != nil {
				log.Printf("Warning: failed to delete checkpoint: %v", err)
			} else {
				log.Println("Checkpoint reset - starting fresh")
			}
		} else {
			checkpoint, err := indexClient.loadCheckpoint(ctx, checkpointKeyName)
			switch {
			case err != nil:
				log.Printf("Warning: failed to load checkpoint: %v", err)
			case checkpoint != nil:
				log.Printf("Resuming from checkpoint: last completed index %d", checkpoint.LastCompletedIndex)
				*startIndex = checkpoint.LastCompletedIndex + 1
				if *startIndex > *endIndex {
					log.Printf("Checkpoint at %d is already past end index %d - nothing to do", checkpoint.LastCompletedIndex, *endIndex)
					return nil
				}
				log.Printf("Processing entries from index %d to %d", *startIndex, *endIndex)
			default:
				log.Printf("No checkpoint found - starting fresh from index %d to %d", *startIndex, *endIndex)
			}
		}

		checkpointChan = make(chan checkpointUpdate, *concurrency*2)
		checkpointDone = make(chan struct{})

		go func() {
			defer close(checkpointDone)

			completedIndices := make(map[int]bool)
			highestCompleted := *startIndex - 1
			saveCounter := 0

			for update := range checkpointChan {
				completedIndices[update.index] = true

				// Find highest contiguous completed index
				if update.index == highestCompleted+1 {
					for i := update.index; completedIndices[i]; i++ {
						highestCompleted = i
						delete(completedIndices, i)
					}
				}

				saveCounter++

				if saveCounter >= *checkpointInterval {
					state := checkpointState{
						LastCompletedIndex: highestCompleted,
						LastUpdated:        time.Now(),
					}
					saveCtx, saveCancel := context.WithTimeout(context.Background(), 5*time.Second)
					if err := indexClient.saveCheckpoint(saveCtx, checkpointKeyName, state); err != nil {
						// If save fails we will try to catch it next time
						log.Printf("Warning: failed to save checkpoint: %v", err)
					} else {
						log.Printf("Checkpoint saved: last completed index %d", highestCompleted)
					}
					saveCancel()
					saveCounter = 0
				}
			}

			state := checkpointState{
				LastCompletedIndex: highestCompleted,
				LastUpdated:        time.Now(),
			}
			saveCtx, saveCancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := indexClient.saveCheckpoint(saveCtx, checkpointKeyName, state); err != nil {
				log.Printf("Warning: failed to save final checkpoint: %v", err)
			} else {
				log.Printf("Final checkpoint saved: last completed index %d", highestCompleted)
			}
			saveCancel()
		}()
	}

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
				return fmt.Errorf("retrieving log uuid by index %d: %w", index, err)
			}

			for uuid, entry := range resp.Payload {
				// uuid is the global UUID - tree ID and entry UUID
				e, _, _, err := unmarshalEntryImpl(entry.Body.(string))
				if err != nil {
					return fmt.Errorf("error unmarshalling entry at index %d for %s: %w", index, uuid, err)
				}
				keys, err := e.IndexKeys()
				if err != nil {
					return fmt.Errorf("error building index keys at index %d for %s: %w", index, uuid, err)
				}
				for _, key := range keys {
					if err := indexClient.idempotentAddToIndex(ctx, key, uuid); err != nil {
						if errors.Is(err, context.Canceled) {
							return nil
						}
						return fmt.Errorf("error inserting UUID %s with key %s at index %d: %w", uuid, key, index, err)
					}
					fmt.Printf("Uploaded entry %s, index %d, key %s\n", uuid, index, key)
				}
			}

			if useCheckpointing {
				select {
				case checkpointChan <- checkpointUpdate{index: index}:
				case <-ctx.Done():
					return nil
				}
			}

			fmt.Printf("Completed log index %d\n", index)
			return nil
		})
	}
	err = group.Wait()

	if useCheckpointing {
		close(checkpointChan)
		<-checkpointDone
	}

	if err != nil {
		if useCheckpointing {
			log.Printf("Backfill failed with error (checkpoint saved, resume from last checkpoint on next run): %v", err)
		}
		return fmt.Errorf("error running backfill: %w", err)
	}

	if useCheckpointing {
		log.Printf("Backfill complete: processed %d entries, checkpoint persists for next run", *endIndex-originalStartIndex+1)
	} else {
		fmt.Println("Backfill complete")
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

// formatRedisCheckpointKey generates a Redis-specific key format for checkpoint storage
func (c *redisClient) formatRedisCheckpointKey(checkpointKey string) string {
	return fmt.Sprintf("backfill/checkpoint/%s", checkpointKey)
}

func (c *redisClient) saveCheckpoint(ctx context.Context, checkpointKey string, state checkpointState) error {
	if *dryRun {
		return nil
	}
	redisKey := c.formatRedisCheckpointKey(checkpointKey)
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshaling checkpoint state: %w", err)
	}
	err = c.client.Set(ctx, redisKey, data, 0).Err()
	if err != nil {
		return fmt.Errorf("saving checkpoint to Redis: %w", err)
	}
	return nil
}

func (c *redisClient) loadCheckpoint(ctx context.Context, checkpointKey string) (*checkpointState, error) {
	redisKey := c.formatRedisCheckpointKey(checkpointKey)
	data, err := c.client.Get(ctx, redisKey).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("loading checkpoint from Redis: %w", err)
	}

	var state checkpointState
	if err := json.Unmarshal([]byte(data), &state); err != nil {
		return nil, fmt.Errorf("unmarshaling checkpoint state: %w", err)
	}
	return &state, nil
}

func (c *redisClient) deleteCheckpoint(ctx context.Context, checkpointKey string) error {
	if *dryRun {
		return nil
	}
	redisKey := c.formatRedisCheckpointKey(checkpointKey)
	err := c.client.Del(ctx, redisKey).Err()
	if err != nil {
		return fmt.Errorf("deleting checkpoint from Redis: %w", err)
	}
	log.Printf("Checkpoint deleted: %s", redisKey)
	return nil
}

func (c *redisClient) supportsCheckpointing() bool {
	return true
}

func (c *mysqlClient) idempotentAddToIndex(ctx context.Context, key, value string) error {
	if *dryRun {
		return nil
	}
	_, err := c.client.NamedExecContext(ctx, mysqlWriteStmt, map[string]any{"key": key, "uuid": value})
	return err
}

func (c *mysqlClient) saveCheckpoint(ctx context.Context, checkpointKey string, state checkpointState) error {
	if *dryRun {
		return nil
	}
	_, err := c.client.NamedExecContext(ctx, mysqlCheckpointSaveStmt, map[string]any{
		"key":       checkpointKey,
		"lastIndex": state.LastCompletedIndex,
	})
	if err != nil {
		return fmt.Errorf("saving checkpoint to MySQL: %w", err)
	}
	return nil
}

func (c *mysqlClient) loadCheckpoint(ctx context.Context, checkpointKey string) (*checkpointState, error) {
	var state checkpointState
	var lastUpdatedBytes []byte
	err := c.client.QueryRowContext(ctx, mysqlCheckpointLoadStmt, checkpointKey).Scan(
		&state.LastCompletedIndex,
		&lastUpdatedBytes,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("loading checkpoint from MySQL: %w", err)
	}

	if len(lastUpdatedBytes) > 0 {
		parsedTime, err := time.Parse("2006-01-02 15:04:05", string(lastUpdatedBytes))
		if err != nil {
			return nil, fmt.Errorf("parsing LastUpdated timestamp: %w", err)
		}
		state.LastUpdated = parsedTime
	}

	return &state, nil
}

func (c *mysqlClient) deleteCheckpoint(ctx context.Context, checkpointKey string) error {
	if *dryRun {
		return nil
	}
	_, err := c.client.ExecContext(ctx, mysqlCheckpointDeleteStmt, checkpointKey)
	if err != nil {
		return fmt.Errorf("deleting checkpoint from MySQL: %w", err)
	}
	log.Printf("Checkpoint deleted: %s", checkpointKey)
	return nil
}

func (c *mysqlClient) supportsCheckpointing() bool {
	return true
}
