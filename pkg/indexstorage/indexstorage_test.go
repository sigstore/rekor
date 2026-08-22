// Copyright 2026 The Sigstore Authors.
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
	"testing"

	"github.com/spf13/viper"
)

func TestMySQLConnLimits(t *testing.T) {
	for _, tc := range []struct {
		name string
		keys map[string]int
		want connLimits
	}{
		{
			name: "nothing configured",
			keys: map[string]int{},
			want: connLimits{},
		},
		{
			// the upgrade case: the deprecated keys sized one pool; the total is now
			// split 70/30 between write and read to preserve the connection budget
			name: "deprecated keys only",
			keys: map[string]int{
				"search_index.mysql.max_open_connections": 10,
				"search_index.mysql.max_idle_connections": 10,
			},
			want: connLimits{readOpen: 3, readIdle: 3, writeOpen: 7, writeIdle: 7},
		},
		{
			name: "per pool only",
			keys: map[string]int{
				"search_index.mysql.read.max_open_connections":  2,
				"search_index.mysql.read.max_idle_connections":  1,
				"search_index.mysql.write.max_open_connections": 8,
				"search_index.mysql.write.max_idle_connections": 4,
			},
			want: connLimits{readOpen: 2, readIdle: 1, writeOpen: 8, writeIdle: 4},
		},
		{
			// mixing deprecated and per-pool keys is unsupported; the deprecated keys
			// are dropped so the per-pool values are used as-is
			name: "mixed keys drops deprecated",
			keys: map[string]int{
				"search_index.mysql.max_open_connections":       10,
				"search_index.mysql.write.max_open_connections": 20,
			},
			want: connLimits{writeOpen: 20},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)
			for k, v := range tc.keys {
				viper.Set(k, v)
			}
			if got := mysqlConnLimits(); got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestPoolLimit(t *testing.T) {
	for _, tc := range []struct {
		name             string
		pool, deprecated int
		write            bool
		want             int
	}{
		{"pool specific wins for read", 5, 10, false, 5},
		{"pool specific wins for write", 5, 10, true, 5},
		{"pool specific wins even when smaller", 1, 9, false, 1},
		{"neither set read", 0, 0, false, 0},
		{"neither set write", 0, 0, true, 0},

		// 70/30 split of deprecated value
		{"deprecated 10 write gets 70%", 0, 10, true, 7},
		{"deprecated 10 read gets remainder", 0, 10, false, 3},
		{"deprecated 3 write", 0, 3, true, 2},
		{"deprecated 3 read", 0, 3, false, 1},

		// floor of 1 prevents 0 (which means unlimited in database/sql)
		{"deprecated 1 write floors to 1", 0, 1, true, 1},
		{"deprecated 1 read floors to 1", 0, 1, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := poolLimit(tc.pool, tc.deprecated, tc.write); got != tc.want {
				t.Errorf("poolLimit(%d, %d, write=%v) = %d, want %d", tc.pool, tc.deprecated, tc.write, got, tc.want)
			}
		})
	}
}
