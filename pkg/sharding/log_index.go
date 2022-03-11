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

// VirtualLogIndex returns the virtual log index for a given leaf index
func VirtualLogIndex(leafIndex int64, tid int64, ranges LogRanges) int64 {
	// if we have no ranges, we have just one log! return the leafIndex as is
	if ranges.Empty() {
		return leafIndex
	}

	var virtualIndex int64
	for _, r := range ranges.GetRanges() {
		if r.TreeID == tid {
			return virtualIndex + leafIndex
		}
		virtualIndex += r.TreeLength
	}
	// this should never happen
	return -1
}
