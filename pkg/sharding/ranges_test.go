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
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/trillian"
	"google.golang.org/grpc"
)

func TestNewLogRanges(t *testing.T) {
	contents := `
- treeID: 0001
  treeLength: 3
  encodedPublicKey: c2hhcmRpbmcK
- treeID: 0002
  treeLength: 4`
	file := filepath.Join(t.TempDir(), "sharding-config")
	if err := os.WriteFile(file, []byte(contents), 0644); err != nil {
		t.Fatal(err)
	}
	treeID := uint(45)
	expected := LogRanges{
		inactive: []LogRange{
			{
				TreeID:           1,
				TreeLength:       3,
				EncodedPublicKey: "c2hhcmRpbmcK",
				decodedPublicKey: "sharding\n",
			}, {
				TreeID:     2,
				TreeLength: 4,
			}},
		active: int64(45),
	}
	ctx := context.Background()
	tc := trillian.NewTrillianLogClient(&grpc.ClientConn{})
	got, err := NewLogRanges(ctx, tc, file, treeID)
	if err != nil {
		t.Fatal(err)
	}
	if expected.ActiveTreeID() != got.ActiveTreeID() {
		t.Fatalf("expected tree id %d got %d", expected.ActiveTreeID(), got.ActiveTreeID())
	}
	if !reflect.DeepEqual(expected.GetInactive(), got.GetInactive()) {
		t.Fatalf("expected %v got %v", expected.GetInactive(), got.GetInactive())
	}
}

func TestLogRangesFromPath(t *testing.T) {
	contents := `
- treeID: 0001
  treeLength: 3
  encodedPublicKey: c2hhcmRpbmcK
- treeID: 0002
  treeLength: 4`
	file := filepath.Join(t.TempDir(), "sharding-config")
	if err := os.WriteFile(file, []byte(contents), 0644); err != nil {
		t.Fatal(err)
	}
	expected := Ranges{
		{
			TreeID:           1,
			TreeLength:       3,
			EncodedPublicKey: "c2hhcmRpbmcK",
		}, {
			TreeID:     2,
			TreeLength: 4,
		},
	}

	got, err := logRangesFromPath(file)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expected, got) {
		t.Fatalf("expected %v got %v", expected, got)
	}
}

func TestLogRangesFromPathJSON(t *testing.T) {
	contents := `[{"treeID": 0001, "treeLength": 3, "encodedPublicKey":"c2hhcmRpbmcK"}, {"treeID": 0002, "treeLength": 4}]`
	file := filepath.Join(t.TempDir(), "sharding-config")
	if err := os.WriteFile(file, []byte(contents), 0644); err != nil {
		t.Fatal(err)
	}
	expected := Ranges{
		{
			TreeID:           1,
			TreeLength:       3,
			EncodedPublicKey: "c2hhcmRpbmcK",
		}, {
			TreeID:     2,
			TreeLength: 4,
		},
	}

	got, err := logRangesFromPath(file)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expected, got) {
		t.Fatalf("expected %v got %v", expected, got)
	}
}

func TestLogRanges_ResolveVirtualIndex(t *testing.T) {
	lrs := LogRanges{
		inactive: []LogRange{
			{TreeID: 1, TreeLength: 17},
			{TreeID: 2, TreeLength: 1},
			{TreeID: 3, TreeLength: 100}},
		active: 4,
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

func TestPublicKey(t *testing.T) {
	ranges := LogRanges{
		active: 45,
		inactive: []LogRange{
			{
				TreeID:           10,
				TreeLength:       10,
				decodedPublicKey: "sharding",
			}, {
				TreeID:     20,
				TreeLength: 20,
			},
		},
	}
	activePubKey := "activekey"
	tests := []struct {
		description    string
		treeID         string
		expectedPubKey string
		shouldErr      bool
	}{
		{
			description:    "empty tree ID",
			expectedPubKey: "activekey",
		}, {
			description:    "tree id with decoded public key",
			treeID:         "10",
			expectedPubKey: "sharding",
		}, {
			description:    "tree id without decoded public key",
			treeID:         "20",
			expectedPubKey: "activekey",
		}, {
			description: "invalid tree id",
			treeID:      "34",
			shouldErr:   true,
		}, {
			description:    "pass in active tree id",
			treeID:         "45",
			expectedPubKey: "activekey",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			got, err := ranges.PublicKey(activePubKey, test.treeID)
			if err != nil && !test.shouldErr {
				t.Fatal(err)
			}
			if test.shouldErr {
				return
			}
			if got != test.expectedPubKey {
				t.Fatalf("got %s doesn't match expected %s", got, test.expectedPubKey)
			}
		})
	}
}
