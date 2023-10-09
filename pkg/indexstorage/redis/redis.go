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

func NewProvider(address, port string) (*IndexStorageProvider, error) {
	provider := &IndexStorageProvider{}
	provider.client = redis.NewClient(&redis.Options{
		Addr:    fmt.Sprintf("%v:%v", address, port),
		Network: "tcp",
		DB:      0, // default DB
	})
	return provider, nil
}

// LookupIndices looks up and returns all indices for the specified key. The key value will be canonicalized
// by converting all characters into a lowercase value before looking up in Redis
func (isp *IndexStorageProvider) LookupIndices(ctx context.Context, key string) ([]string, error) {
	if isp.client == nil {
		return []string{}, errors.New("redis client has not been initialized")
	}
	return isp.client.LRange(ctx, strings.ToLower(key), 0, -1).Result()
}

// WriteIndex adds the index for the specified key. The key value will be canonicalized
// by converting all characters into a lowercase value before appending the index in Redis
func (isp *IndexStorageProvider) WriteIndex(ctx context.Context, key, index string) error {
	if isp.client == nil {
		return errors.New("redis client has not been initialized")
	}
	if _, err := isp.client.LPush(ctx, strings.ToLower(key), index).Result(); err != nil {
		return fmt.Errorf("redis client: %w", err)
	}
	return nil
}
