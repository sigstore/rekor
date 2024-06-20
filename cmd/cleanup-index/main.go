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
	cleanup-index checks what index entries are in the MySQL table and deletes those entries from the Redis databse.
	It does not go the other way

	To run:
	go run cmd/cleanup-index/main.go --mysql-dsn <mysql connection> --redis-hostname <redis-hostname> --redis-port <redis-port> [--dry-run]
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
	"syscall"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/redis/go-redis/v9"
	"sigs.k8s.io/release-utils/version"

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
	mysqlSelectStmt = "SELECT DISTINCT EntryKey FROM EntryIndex"
)

var (
	redisHostname           = flag.String("redis-hostname", "", "Hostname for Redis application")
	redisPort               = flag.String("redis-port", "", "Port to Redis application")
	redisPassword           = flag.String("redis-password", "", "Password for Redis authentication")
	redisEnableTLS          = flag.Bool("redis-enable-tls", false, "Enable TLS for Redis client")
	redisInsecureSkipVerify = flag.Bool("redis-insecure-skip-verify", false, "Whether to skip TLS verification for Redis client or not")
	mysqlDSN                = flag.String("mysql-dsn", "", "MySQL Data Source Name")
	versionFlag             = flag.Bool("version", false, "Print the current version of cleanup-index")
	dryRun                  = flag.Bool("dry-run", false, "Dry run - don't actually delete from Redis")
)

func main() {
	flag.Parse()

	versionInfo := version.GetVersionInfo()
	if *versionFlag {
		fmt.Println(versionInfo.String())
		os.Exit(0)
	}

	if *mysqlDSN == "" {
		log.Fatal("mysql-dsn must be set")
	}
	if *redisHostname == "" {
		log.Fatal("redis-hostname must be set")
	}
	if *redisPort == "" {
		log.Fatal("redis-port must be set")
	}

	log.Printf("running cleanup index Version: %s GitCommit: %s BuildDate: %s", versionInfo.GitVersion, versionInfo.GitCommit, versionInfo.BuildDate)

	redisClient := getRedisClient()

	mysqlClient, err := getMySQLClient()
	if err != nil {
		log.Fatalf("creating mysql client: %v", err)
	}

	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	err = batchQueryAndDelete(ctx, mysqlClient, redisClient)
	if err != nil {
		log.Fatal(err)
	}
}

// getRedisClient creates a Redis client.
func getRedisClient() *redis.Client {
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
	return redis.NewClient(opts)
}

// getMySQLClient creates a MySQL client.
func getMySQLClient() (*sqlx.DB, error) {
	dbClient, err := sqlx.Open("mysql", *mysqlDSN)
	if err != nil {
		return nil, err
	}
	if err = dbClient.Ping(); err != nil {
		return nil, err
	}
	return dbClient, nil
}

// batchQueryAndDelete looks up entries in the EntryIndex table in MySQL and removes them from Redis.
// The SQL query is processed in batches because the entire data set is too large to store in memory at once.
func batchQueryAndDelete(ctx context.Context, dbClient *sqlx.DB, redisClient *redis.Client) error {
	const batchSize = 10000
	keys := [batchSize]string{}
	rows, err := dbClient.QueryContext(ctx, mysqlSelectStmt)
	if err != nil {
		return err
	}
	defer rows.Close()
	index := 0
	batchIndex := 1
	for rows.Next() {
		if err := rows.Scan(&keys[index]); err != nil {
			return err
		}
		index++
		if index == batchSize {
			if err := removeFromRedis(ctx, redisClient, keys[:], batchIndex); err != nil {
				return err
			}
			index = 0
			batchIndex++
		}
	}
	if index != 0 {
		if err := removeFromRedis(ctx, redisClient, keys[:index], batchIndex); err != nil {
			return err
		}
	}
	return nil
}

// removeFromRedis delete the given keys from Redis.
func removeFromRedis(ctx context.Context, redisClient *redis.Client, keys []string, batchIndex int) error {
	fmt.Printf("attempting to remove %d keys from redis (batch %d)\n", len(keys), batchIndex)
	if *dryRun {
		return nil
	}
	result, err := redisClient.Del(ctx, keys...).Result()
	if err != nil {
		return err
	}
	fmt.Printf("removed %d keys from redis\n", result)
	if result != int64(len(keys)) {
		fmt.Println("some keys present in mysql may already have been removed from redis")
	}
	return nil
}
