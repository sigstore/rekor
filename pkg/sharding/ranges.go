//
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
	"fmt"
	"strings"
)

type LogRanges struct {
	ranges []LogRange
}

type LogRange struct {
	TreeID     int64
	TreeLength int64
}

func (l *LogRanges) ResolveVirtualIndex(index int) (int64, int64) {
	indexLeft := index
	for _, l := range l.ranges {
		if indexLeft < int(l.TreeLength) {
			return l.TreeID, int64(indexLeft)
		}
		indexLeft -= int(l.TreeLength)
	}

	// Return the last one!
	return l.ranges[len(l.ranges)-1].TreeID, int64(indexLeft)
}

// ActiveIndex returns the active shard index, always the last shard in the range
func (l *LogRanges) ActiveIndex() int64 {
	return l.ranges[len(l.ranges)-1].TreeID
}

func (l *LogRanges) Empty() bool {
	return l.ranges == nil
}

// TotalLength returns the total length across all shards
func (l *LogRanges) TotalLength() int64 {
	var total int64
	for _, r := range l.ranges {
		total += r.TreeLength
	}
	return total
}

func (l *LogRanges) SetRanges(r []LogRange) {
	l.ranges = r
}

func (l *LogRanges) GetRanges() []LogRange {
	return l.ranges
}

func (l *LogRanges) AppendRange(r LogRange) {
	l.ranges = append(l.ranges, r)
}

func (l *LogRanges) String() string {
	ranges := []string{}
	for _, r := range l.ranges {
		ranges = append(ranges, fmt.Sprintf("%d=%d", r.TreeID, r.TreeLength))
	}
	return strings.Join(ranges, ",")
}
