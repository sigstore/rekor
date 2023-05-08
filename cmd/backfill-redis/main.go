// Copyright 2022 The Sigstore Authors.
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
	backfill-redis is a script to populate the Redis index with entries
	from Rekor. This is sometimes necessary because Redis caching is best
	effort. If Redis returns an error, Rekor will not, and so sometimes
	we need to backfill missing entries into Redis for the search API.

	To run:
	go run cmd/backfill-redis/main.go --rekor-address <address> \
	    --hostname <redis-hostname> --port <redis-port>
		--start <first index to backfill> --end <last index to backfill>
*/

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/go-openapi/runtime"
	"github.com/redis/go-redis/v9"
	"sigs.k8s.io/release-utils/version"

	"github.com/sigstore/rekor/pkg/client"
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

	// remove 0.0.2 intoto type due to bugs
	// _ "github.com/sigstore/rekor/pkg/types/intoto/v0.0.2"
	_ "github.com/sigstore/rekor/pkg/types/jar/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/rfc3161/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/rpm/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/tuf/v0.0.1"
)

var (
	redisHostname = flag.String("hostname", "", "Hostname for Redis application")
	redisPort     = flag.String("port", "", "Port to Redis application")
	startIndex    = flag.Int("start", -1, "First index to backfill")
	endIndex      = flag.Int("end", -1, "Last index to backfill")
	rekorAddress  = flag.String("rekor-address", "", "Address for Rekor, e.g. https://rekor.sigstore.dev")
	versionFlag   = flag.Bool("version", false, "Print the current version of Backfill Redis")
)

func main() {
	flag.Parse()

	versionInfo := version.GetVersionInfo()
	if *versionFlag {
		fmt.Println(versionInfo.String())
		os.Exit(0)
	}

	if *redisHostname == "" {
		log.Fatal("address must be set")
	}
	if *redisPort == "" {
		log.Fatal("port must be set")
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

	log.Printf("running backfill redis Version: %s GitCommit: %s BuildDate: %s", versionInfo.GitVersion, versionInfo.GitCommit, versionInfo.BuildDate)

	redisClient := redis.NewClient(&redis.Options{
		Addr:    fmt.Sprintf("%s:%s", *redisHostname, *redisPort),
		Network: "tcp",
		DB:      0, // default DB
	})

	rekorClient, err := client.GetRekorClient(*rekorAddress)
	if err != nil {
		log.Fatalf("creating rekor client: %v", err)
	}

	for i := *startIndex; i <= *endIndex; i++ {
		params := entries.NewGetLogEntryByIndexParamsWithContext(context.Background())
		params.SetLogIndex(int64(i))
		resp, err := rekorClient.Entries.GetLogEntryByIndex(params)
		if err != nil {
			log.Fatalf("retrieving log uuid by index: %v", err)
		}
		var insertErrs []error
		for uuid, entry := range resp.Payload {
			// uuid is the global UUID - tree ID and entry UUID
			e, _, _, err := unmarshalEntryImpl(entry.Body.(string))
			if err != nil {
				insertErrs = append(insertErrs, fmt.Errorf("error unmarshalling entry for %s: %v", uuid, err))
				continue
			}
			keys, err := e.IndexKeys()
			if err != nil {
				insertErrs = append(insertErrs, fmt.Errorf("error building index keys for %s: %v", uuid, err))
				continue
			}
			for _, key := range keys {
				// remove the key-value pair from the index in case it already exists
				if err := removeFromIndex(context.Background(), redisClient, key, uuid); err != nil {
					insertErrs = append(insertErrs, fmt.Errorf("error removing UUID %s with key %s: %v", uuid, key, err))
				}
				if err := addToIndex(context.Background(), redisClient, key, uuid); err != nil {
					insertErrs = append(insertErrs, fmt.Errorf("error inserting UUID %s with key %s: %v", uuid, key, err))
				}
				fmt.Printf("Uploaded Redis entry %s, index %d, key %s\n", uuid, i, key)
			}
		}
		if len(insertErrs) != 0 {
			fmt.Printf("Errors with log index %d:\n", i)
			for _, e := range insertErrs {
				fmt.Println(e)
			}
		} else {
			fmt.Printf("Completed log index %d\n", i)
		}
	}
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

// removeFromIndex removes all occurrences of a value from a given key. This guards against
// multiple invocations of backfilling creating duplicates.
func removeFromIndex(ctx context.Context, redisClient *redis.Client, key, value string) error {
	_, err := redisClient.LRem(ctx, key, 0, value).Result()
	return err
}

// addToIndex pushes a value onto a key of type list.
func addToIndex(ctx context.Context, redisClient *redis.Client, key, value string) error {
	_, err := redisClient.LPush(ctx, key, value).Result()
	return err
}
