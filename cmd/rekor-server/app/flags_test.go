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
	"github.com/sigstore/rekor/pkg/sharding"
)

func TestLogRanges_Set(t *testing.T) {
	tests := []struct {
		name   string
		arg    string
		want   []sharding.LogRange
		active uint64
	}{
		{
			name: "one, no length",
			arg:  "1234",
			want: []sharding.LogRange{
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
			want: []sharding.LogRange{
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
			l := &LogRangesFlag{}
			if err := l.Set(tt.arg); err != nil {
				t.Errorf("LogRanges.Set() expected no error, got %v", err)
			}

			if diff := cmp.Diff(tt.want, l.Ranges.Ranges); diff != "" {
				t.Errorf(diff)
			}

			active := l.Ranges.ActiveIndex()
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
			l := &LogRangesFlag{}
			if err := l.Set(tt.arg); err == nil {
				t.Error("LogRanges.Set() expected error but got none")
			}
		})
	}
}
