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
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
)

type LogRanges struct {
	ranges Ranges
}

type Ranges []LogRange

type LogRange struct {
	TreeID     int64 `yaml:"treeID"`
	TreeLength int64 `yaml:"treeLength"`
}

func NewLogRanges(path string, treeID string) (LogRanges, error) {
	if path == "" {
		return LogRanges{}, nil
	}
	id, err := strconv.Atoi(treeID)
	if err != nil {
		return LogRanges{}, errors.Wrapf(err, "%s is not a valid int64", treeID)
	}
	// otherwise, try to read contents of the sharding config
	var ranges Ranges
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return LogRanges{}, err
	}
	if err := yaml.Unmarshal(contents, &ranges); err != nil {
		return LogRanges{}, err
	}
	ranges = append(ranges, LogRange{TreeID: int64(id)})
	return LogRanges{
		ranges: ranges,
	}, nil
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

// ActiveTreeID returns the active shard index, always the last shard in the range
func (l *LogRanges) ActiveTreeID() int64 {
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
