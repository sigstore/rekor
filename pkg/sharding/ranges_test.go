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
	"io/ioutil"
	"path/filepath"
	"reflect"
	"testing"
)

func TestNewLogRanges(t *testing.T) {
	contents := `
- treeID: 0001
  treeLength: 3
- treeID: 0002
  treeLength: 4`
	file := filepath.Join(t.TempDir(), "sharding-config")
	if err := ioutil.WriteFile(file, []byte(contents), 0644); err != nil {
		t.Fatal(err)
	}
	treeID := "45"
	expected := LogRanges{
		activeTreeID: 45,
		ranges: []LogRange{
			{
				TreeID:     1,
				TreeLength: 3,
			}, {
				TreeID:     2,
				TreeLength: 4,
			},
		},
	}
	got, err := NewLogRanges(file, treeID)
	if err != nil {
		t.Fatal(err)
	}
	if expected.ActiveTreeID() != got.ActiveTreeID() {
		t.Fatalf("expected tree id %d got %d", expected.ActiveTreeID(), got.ActiveTreeID())
	}
	if !reflect.DeepEqual(expected.GetRanges(), got.GetRanges()) {
		t.Fatalf("expected %v got %v", expected.GetRanges(), got.GetRanges())
	}
}

func TestLogRanges_ResolveVirtualIndex(t *testing.T) {
	lrs := LogRanges{
		ranges: []LogRange{
			{TreeID: 1, TreeLength: 17},
			{TreeID: 2, TreeLength: 1},
			{TreeID: 3, TreeLength: 100},
			{TreeID: 4},
		},
	}

	for _, tt := range []struct {
		Index      int
		WantTreeID int64
		WantIndex  int64
	}{
		{
			Index:      3,
			WantTreeID: 1, WantIndex: 3,
		},
		// This is the first (0th) entry in the next tree
		{
			Index:      17,
			WantTreeID: 2, WantIndex: 0,
		},
		// Overflow
		{
			Index:      3000,
			WantTreeID: 4, WantIndex: 2882,
		},
	} {
		tree, index := lrs.ResolveVirtualIndex(tt.Index)
		if tree != tt.WantTreeID {
			t.Errorf("LogRanges.ResolveVirtualIndex() tree = %v, want %v", tree, tt.WantTreeID)
		}
		if index != tt.WantIndex {
			t.Errorf("LogRanges.ResolveVirtualIndex() index = %v, want %v", index, tt.WantIndex)
		}
	}
}
