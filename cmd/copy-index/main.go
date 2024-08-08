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
	copy-index is a script to copy indexes from one provider to another.
	Currently, only copying from Redis to MySQL is supported. This is useful
	when the data already exists in one backend and needs to be migrated to a
	new provider.

	To run:
	go run cmd/copy-index/main.go --redis-hostname <redis-hostname> --redis-port <redis-port> \
		--mysql-dsn <mysql-dsn> [--dry-run]
*/

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/redis/go-redis/v9"
	"sigs.k8s.io/release-utils/version"
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

type redisClient struct {
	client *redis.Client
	cursor int
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
	batchSize               = flag.Int("batch-size", 10000, "Number of Redis entries to scan per batch (use for testing)")
	versionFlag             = flag.Bool("version", false, "Print the current version of Copy Index")
	dryRun                  = flag.Bool("dry-run", false, "Dry run - don't actually insert into MySQL")
)

func main() {
	flag.Parse()

	versionInfo := version.GetVersionInfo()
	if *versionFlag {
		fmt.Println(versionInfo.String())
		os.Exit(0)
	}

	if *redisHostname == "" {
		log.Fatal("Redis address must be set")
	}
	if *redisPort == "" {
		log.Fatal("Redis port must be set")
	}
	if *mysqlDSN == "" {
		log.Fatal("MySQL DSN must be set")
	}

	log.Printf("running copy index Version: %s GitCommit: %s BuildDate: %s", versionInfo.GitVersion, versionInfo.GitCommit, versionInfo.BuildDate)

	mysqlClient, err := getMySQLClient()
	if err != nil {
		log.Fatalf("creating mysql client: %v", err)
	}
	redisClient, err := getRedisClient()
	if err != nil {
		log.Fatalf("creating redis client: %v", err)
	}

	err = doCopy(mysqlClient, redisClient)
	if err != nil {
		log.Fatalf("populating index: %v", err)
	}
}

// getMySQLClient creates a MySQL client.
func getMySQLClient() (*mysqlClient, error) {
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
}

// getRedisClient creates a Redis client.
func getRedisClient() (*redisClient, error) {
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
}

// doCopy pulls search index entries from the Redis database and copies them into the MySQL database.
func doCopy(mysqlClient *mysqlClient, redisClient *redisClient) error {
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	var err error
	var done bool
	var keys []string
	for !done {
		keys, done, err = redisClient.getIndexKeys(ctx)
		if err != nil {
			return err
		}
		for _, k := range keys {
			uuids, err := redisClient.getUUIDsForKey(ctx, k)
			if err != nil {
				return err
			}
			for _, v := range uuids {
				err = mysqlClient.idempotentAddToIndex(ctx, k, v)
				if err != nil {
					return err
				}
			}
		}
	}
	fmt.Println("Copy complete")
	return nil
}

// getIndexKeys looks up every key in Redis that is not a checkpoint string.
// It limits the size of the scan to the value of --batch-size and uses the
// returned cursor to keep track of whether the scan is complete.
// It returns a boolean true when the call does not need to be repeated to get more keys.
func (c *redisClient) getIndexKeys(ctx context.Context) ([]string, bool, error) {
	result, err := c.client.Do(ctx, "SCAN", c.cursor, "TYPE", "list", "COUNT", *batchSize).Result() // go-redis Scan method does not support TYPE
	if err != nil {
		return nil, false, err
	}
	resultList, ok := result.([]any)
	if !ok {
		return nil, false, fmt.Errorf("unexpected result from Redis SCAN command: %v", result)
	}
	if len(resultList) != 2 {
		return nil, false, fmt.Errorf("unexpected result from Redis SCAN command: %v", resultList)
	}
	cursor, ok := resultList[0].(string)
	if !ok {
		return nil, false, fmt.Errorf("could not parse returned cursor from Redis SCAN command: %v", resultList[0])
	}
	c.cursor, err = strconv.Atoi(cursor)
	if err != nil {
		return nil, false, fmt.Errorf("could not parse returned cursor from Redis SCAN command: %v", cursor)
	}
	keys, ok := resultList[1].([]any)
	if !ok {
		return nil, false, fmt.Errorf("could not parse returned keys from Redis SCAN command: %v", resultList[1])
	}
	keyStrings := make([]string, len(keys))
	for i, k := range keys {
		keyStrings[i], ok = k.(string)
		if !ok {
			return nil, false, fmt.Errorf("could not parse returned keys from Redis SCAN command: %v", k)
		}
	}
	fmt.Printf("Processing %d keys - cursor %d\n", len(keys), c.cursor)
	return keyStrings, c.cursor == 0, nil
}

// getUUIDsForKey returns the list of UUIDs for a given index key.
func (c *redisClient) getUUIDsForKey(ctx context.Context, key string) ([]string, error) {
	return c.client.LRange(ctx, key, 0, -1).Result()
}

// idempotentAddToIndex inserts the given key-value pair into the MySQL search index table.
func (c *mysqlClient) idempotentAddToIndex(ctx context.Context, key, value string) error {
	if *dryRun {
		return nil
	}
	_, err := c.client.NamedExecContext(ctx, mysqlWriteStmt, map[string]any{"key": key, "uuid": value})
	return err
}
