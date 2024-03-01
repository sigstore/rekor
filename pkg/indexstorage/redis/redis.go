// Copyright 2023 The Sigstore Authors.
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

package redis

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"

	redis "github.com/redis/go-redis/v9"
)

const ProviderType = "redis"

// IndexStorageProvider implements indexstorage.IndexStorage
type IndexStorageProvider struct {
	client *redis.Client
}

func NewProvider(address, port, password string, enableTLS bool, insecureSkipVerify bool) (*IndexStorageProvider, error) {
	provider := &IndexStorageProvider{}
	provider.client = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%v:%v", address, port),
		Network:  "tcp",
		Password: password,
		DB:       0, // default DB
	})

	// #nosec G402
	if enableTLS {
		provider.client.Options().TLSConfig = &tls.Config{
			InsecureSkipVerify: insecureSkipVerify, //nolint: gosec
		}
	}
	return provider, nil
}

// LookupIndices looks up and returns all indices for the specified key(s). The key value(s) will be canonicalized
// by converting all characters into a lowercase value before looking up in Redis
func (isp *IndexStorageProvider) LookupIndices(ctx context.Context, keys []string) ([]string, error) {
	if isp.client == nil {
		return []string{}, errors.New("redis client has not been initialized")
	}
	cmds, err := isp.client.Pipelined(ctx, func(pipe redis.Pipeliner) error {
		for _, key := range keys {
			pipe.LRange(ctx, strings.ToLower(key), 0, -1)
		}
		return nil
	})
	if err != nil {
		return []string{}, fmt.Errorf("redis client: %w", err)
	}
	var result []string
	for _, cmd := range cmds {
		result = append(result, cmd.(*redis.StringSliceCmd).Val()...)
	}
	return result, nil
}

// WriteIndex adds the index for the specified keys. The key value(s) will be canonicalized
// by converting all characters into a lowercase value before appending the index in Redis
func (isp *IndexStorageProvider) WriteIndex(ctx context.Context, keys []string, index string) error {
	if isp.client == nil {
		return errors.New("redis client has not been initialized")
	}
	_, err := isp.client.Pipelined(ctx, func(pipe redis.Pipeliner) error {
		for _, key := range keys {
			pipe.LPush(ctx, strings.ToLower(key), index)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("redis client: %w", err)
	}
	return nil
}

// Shutdown cleans up any client resources that may be held by the provider
func (isp *IndexStorageProvider) Shutdown() error {
	if isp.client == nil {
		return nil
	}
	return isp.client.Close()
}
