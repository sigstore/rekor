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
		ranges        LogRanges
		expectedIndex int64
	}{
		{
			description:   "no ranges",
			leafIndex:     5,
			expectedIndex: 5,
		},
		// Log 100: 0 1 2 3 4
		// Log 300: 5 6 7
		{
			description: "two shards",
			leafIndex:   2,
			ranges: LogRanges{
				Ranges: []LogRange{
					{
						TreeID:     100,
						TreeLength: 5,
					}, {
						TreeID: 300,
					},
				},
			},
			expectedIndex: 7,
		}, {
			description: "three shards",
			leafIndex:   0,
			ranges: LogRanges{
				Ranges: []LogRange{
					{
						TreeID:     100,
						TreeLength: 5,
					}, {
						TreeID:     300,
						TreeLength: 0,
					}, {
						TreeID: 400,
					},
				},
			},
			expectedIndex: 5,
		}, {
			description: "ranges is empty but not-nil",
			leafIndex:   2,
			ranges: LogRanges{
				Ranges: []LogRange{
					{
						TreeID: 30,
					},
				},
			},
			expectedIndex: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			got := VirtualLogIndex(test.leafIndex, &test.ranges)
			if got != test.expectedIndex {
				t.Fatalf("expected %v got %v", test.expectedIndex, got)
			}
		})
	}
}
