// Copyright 2021 The Sigstore Authors.
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

package sharding

import (
	"testing"
)

func TestVirtualLogIndex(t *testing.T) {
	tests := []struct {
		description   string
		leafIndex     int64
		tid           int64
		ranges        LogRanges
		expectedIndex int64
	}{
		{
			description:   "no ranges",
			leafIndex:     5,
			ranges:        LogRanges{},
			expectedIndex: 5,
		},
		// Log 100: 0 1 2 3 4
		// Log 300: 5 6 7...
		{
			description: "two shards",
			leafIndex:   2,
			tid:         300,
			ranges: LogRanges{
				inactive: []LogRange{
					{
						TreeID:     100,
						TreeLength: 5,
					}},
				active: LogRange{TreeID: 300},
			},
			expectedIndex: 7,
		},
		// Log 100: 0 1 2 3 4
		// Log 300: 5 6 7 8
		// Log 400: ...
		{
			description: "three shards",
			leafIndex:   1,
			tid:         300,
			ranges: LogRanges{
				inactive: []LogRange{
					{
						TreeID:     100,
						TreeLength: 5,
					}, {
						TreeID:     300,
						TreeLength: 4,
					}},
				active: LogRange{TreeID: 400},
			},
			expectedIndex: 6,
		},
		// Log 30: 1 2 3...
		{
			description: "only active tree",
			leafIndex:   2,
			tid:         30,
			ranges: LogRanges{
				active: LogRange{TreeID: 30},
			},
			expectedIndex: 2,
		}, {
			description: "invalid tid passed in",
			leafIndex:   2,
			tid:         4,
			ranges: LogRanges{
				active: LogRange{TreeID: 30},
			},
			expectedIndex: -1,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			got := VirtualLogIndex(test.leafIndex, test.tid, test.ranges)
			if got != test.expectedIndex {
				t.Fatalf("expected %v got %v", test.expectedIndex, got)
			}
		})
	}
}
