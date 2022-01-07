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

type LogRanges struct {
	Ranges []LogRange
}

type LogRange struct {
	TreeID     uint64
	TreeLength uint64
}

func (l *LogRanges) ResolveVirtualIndex(index int) (uint64, uint64) {
	indexLeft := index
	for _, l := range l.Ranges {
		if indexLeft < int(l.TreeLength) {
			return l.TreeID, uint64(indexLeft)
		}
		indexLeft -= int(l.TreeLength)
	}

	// Return the last one!
	return l.Ranges[len(l.Ranges)-1].TreeID, uint64(indexLeft)
}

// ActiveIndex returns the active shard index, always the last shard in the range
func (l *LogRanges) ActiveIndex() uint64 {
	return l.Ranges[len(l.Ranges)-1].TreeID
}
