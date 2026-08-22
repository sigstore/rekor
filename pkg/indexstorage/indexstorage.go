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

	"github.com/sigstore/rekor/pkg/indexstorage/mysql"
	"github.com/sigstore/rekor/pkg/indexstorage/redis"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/spf13/viper"
)

type IndexStorage interface {
	LookupIndices(context.Context, []string) ([]string, error) // Returns indices for specified keys
	WriteIndex(context.Context, []string, string) error        // Writes index for specified keys
	Shutdown() error                                           // Method to run on shutdown
}

// NewIndexStorage instantiates a new IndexStorage provider based on the requested type
func NewIndexStorage(providerType string) (IndexStorage, error) {
	switch providerType {
	case redis.ProviderType:
		return redis.NewProvider(viper.GetString("redis_server.address"), viper.GetString("redis_server.port"), viper.GetString("redis_server.password"), viper.GetBool("redis_server.enable-tls"), viper.GetBool("redis_server.insecure-skip-verify"))
	case mysql.ProviderType:
		limits := mysqlConnLimits()
		return mysql.NewProvider(viper.GetString("search_index.mysql.dsn"),
			mysql.WithConnMaxIdleTime(viper.GetDuration("search_index.mysql.conn_max_idletime")),
			mysql.WithConnMaxLifetime(viper.GetDuration("search_index.mysql.conn_max_lifetime")),
			mysql.WithReadMaxIdleConns(limits.readIdle),
			mysql.WithReadMaxOpenConns(limits.readOpen),
			mysql.WithWriteMaxIdleConns(limits.writeIdle),
			mysql.WithWriteMaxOpenConns(limits.writeOpen))
	default:
		return nil, fmt.Errorf("invalid index storage provider type: %v", providerType)
	}
}

type connLimits struct {
	readOpen, readIdle   int
	writeOpen, writeIdle int
}

// mysqlConnLimits resolves each index pool's connection limits from viper.
func mysqlConnLimits() connLimits {
	// the deprecated keys sized a single pool; the total is now split 70/30 between the
	// write and read pools so the operator's original connection budget is preserved
	deprecatedOpen := viper.GetInt("search_index.mysql.max_open_connections")
	deprecatedIdle := viper.GetInt("search_index.mysql.max_idle_connections")
	hasDeprecated := deprecatedOpen != 0 || deprecatedIdle != 0

	readOpen := viper.GetInt("search_index.mysql.read.max_open_connections")
	readIdle := viper.GetInt("search_index.mysql.read.max_idle_connections")
	writeOpen := viper.GetInt("search_index.mysql.write.max_open_connections")
	writeIdle := viper.GetInt("search_index.mysql.write.max_idle_connections")
	hasPerPool := readOpen != 0 || readIdle != 0 || writeOpen != 0 || writeIdle != 0

	if hasDeprecated && hasPerPool {
		log.Logger.Warnf("search_index.mysql.max_open_connections / max_idle_connections must not be mixed " +
			"with the per-pool search_index.mysql.read.* / write.* keys; the deprecated keys will be ignored")
		deprecatedOpen = 0
		deprecatedIdle = 0
	} else if hasDeprecated {
		log.Logger.Warnf("search_index.mysql.max_open_connections and max_idle_connections are deprecated " +
			"and will be split 70/30 between the write and read pools; " +
			"set the search_index.mysql.read.* and search_index.mysql.write.* keys instead")
	}

	return connLimits{
		readOpen:  poolLimit(readOpen, deprecatedOpen, false),
		readIdle:  poolLimit(readIdle, deprecatedIdle, false),
		writeOpen: poolLimit(writeOpen, deprecatedOpen, true),
		writeIdle: poolLimit(writeIdle, deprecatedIdle, true),
	}
}

// poolLimit prefers a pool-specific connection limit, falling back to a 70/30
// (write/read) split of the deprecated unprefixed key that predates the read/write
// pool split. The split preserves the operator's original total connection budget.
func poolLimit(pool, deprecated int, write bool) int {
	if pool != 0 {
		return pool
	}
	if deprecated == 0 {
		return 0
	}
	w := max(deprecated*7/10, 1)
	if write {
		return w
	}
	return max(deprecated-w, 1)
}
