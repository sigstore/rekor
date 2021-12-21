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

package app

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestLogRanges_Set(t *testing.T) {
	tests := []struct {
		name   string
		arg    string
		want   []LogRange
		active uint64
	}{
		{
			name: "one, no length",
			arg:  "1234",
			want: []LogRange{
				{
					TreeID:     1234,
					TreeLength: 0,
				},
			},
			active: 1234,
		},
		{
			name: "two",
			arg:  "1234=10,7234",
			want: []LogRange{
				{
					TreeID:     1234,
					TreeLength: 10,
				},
				{
					TreeID:     7234,
					TreeLength: 0,
				},
			},
			active: 7234,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &LogRanges{}
			if err := l.Set(tt.arg); err != nil {
				t.Errorf("LogRanges.Set() expected no error, got %v", err)
			}

			if diff := cmp.Diff(tt.want, l.Ranges); diff != "" {
				t.Errorf(diff)
			}

			active := l.ActiveIndex()
			if active != tt.active {
				t.Errorf("LogRanges.Active() expected %d no error, got %d", tt.active, active)
			}
		})
	}
}

func TestLogRanges_SetErr(t *testing.T) {
	tests := []struct {
		name string
		arg  string
	}{
		{
			name: "one, length (error)",
			arg:  "1234=10",
		},
		{
			name: "two, length (error)",
			arg:  "1234=10,7234=17",
		},
		{
			name: "invalid",
			arg:  "1234=10,7234-17",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &LogRanges{}
			if err := l.Set(tt.arg); err == nil {
				t.Error("LogRanges.Set() expected error but got none")
			}
		})
	}
}

func TestLogRanges_ResolveVirtualIndex(t *testing.T) {
	lrs := LogRanges{
		Ranges: []LogRange{
			{TreeID: 1, TreeLength: 17},
			{TreeID: 2, TreeLength: 1},
			{TreeID: 3, TreeLength: 100},
			{TreeID: 4},
		},
	}

	for _, tt := range []struct {
		Index      int
		WantTreeID uint64
		WantIndex  uint64
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
