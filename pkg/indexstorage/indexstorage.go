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

package indexstorage

import (
	"context"
	"fmt"

	"github.com/sigstore/rekor/pkg/indexstorage/redis"
	"github.com/spf13/viper"
)

type IndexStorage interface {
	LookupIndices(context.Context, string) ([]string, error) // Returns indices for specified key
	WriteIndex(context.Context, string, string) error        // Writes index for specified key
}

// NewIndexStorage instantiates a new IndexStorage provider based on the requested type
func NewIndexStorage(providerType string) (IndexStorage, error) {
	switch providerType {
	case redis.ProviderType:
		return redis.NewProvider(viper.GetString("redis_server.address"), viper.GetString("redis_server.port"), viper.GetString("redis_server.password"))
	default:
		return nil, fmt.Errorf("invalid index storage provider type: %v", providerType)
	}
}
