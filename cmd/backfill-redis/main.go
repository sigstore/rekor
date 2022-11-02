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

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"log"

	"github.com/go-openapi/runtime"
	radix "github.com/mediocregopher/radix/v4"
	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/types"

	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
)

var (
	redisAddress = flag.String("address", "", "Address for Redis application")
	redisPort    = flag.String("port", "", "Port to Redis application")
	startIndex   = flag.Int("start", -1, "First index to backfill")
	endIndex     = flag.Int("end", -1, "Last index to backfill")
	rekorAddress = flag.String("rekor-address", "", "Address for Rekor, e.g. https://rekor.sigstore.dev")
)

func main() {
	flag.Parse()

	if *redisAddress == "" {
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

	cfg := radix.PoolConfig{}
	redisClient, err := cfg.New(context.Background(), "tcp", fmt.Sprintf("%s:%s", *redisAddress, *redisPort))
	if err != nil {
		log.Fatal(err)
	}

	rekorClient, err := client.GetRekorClient("https://rekor.sigstore.dev")
	if err != nil {
		log.Fatalf("creating rekor client: %v", err)
	}

	for i := *startIndex; i <= *endIndex; i++ {
		params := entries.NewGetLogEntryByIndexParamsWithContext(context.Background())
		params.SetLogIndex(int64(*startIndex))
		resp, err := rekorClient.Entries.GetLogEntryByIndex(params)
		if err != nil {
			log.Fatalf("retrieving log uuid by index: %v", err)
		}
		for uuid, entry := range resp.Payload {
			// uuid is the global UUID - tree ID and entry UUID
			e, _, _, err := unmarshalEntryImpl(entry.Body.(string))
			if err != nil {
				fmt.Printf("error unmarshalling entry for %s: %v\n", uuid, err)
				continue
			}
			keys, err := e.IndexKeys()
			if err != nil {
				fmt.Printf("error building index keys for %s: %v\n", uuid, err)
				continue
			}
			for _, key := range keys {
				if err := addToIndex(context.Background(), redisClient, key, uuid); err != nil {
					fmt.Printf("error inserting UUID %s with key %s: %v\n", uuid, key, err)
				}
				fmt.Printf("Uploaded Redis entry %s, index %d, key %s\n", uuid, i, key)
			}
		}
		fmt.Printf("Completed log index %d\n", i)
	}
}

// unmarshalEntryImpl decodes the base64-encoded entry to a specific entry type (types.EntryImpl).
// from cosign
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

func addToIndex(ctx context.Context, redisClient radix.Client, key, value string) error {
	return redisClient.Do(ctx, radix.Cmd(nil, "LPUSH", key, value))
}
