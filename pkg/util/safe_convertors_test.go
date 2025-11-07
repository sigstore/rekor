// Copyright 2022 The Sigstore Authors.
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

package util

import (
	"math"
	"testing"
)

func TestSafeUint64ToInt64(t *testing.T) {
	tests := []struct {
		name      string
		input     uint64
		want      int64
		wantErr   bool
	}{
		{
			name:    "small positive number",
			input:   42,
			want:    42,
			wantErr: false,
		},
		{
			name:    "zero value",
			input:   0,
			want:    0,
			wantErr: false,
		},
		{
			name:    "max int64 boundary",
			input:   uint64(math.MaxInt64),
			want:    math.MaxInt64,
			wantErr: false,
		},
		{
			name:    "overflow beyond int64",
			input:   uint64(math.MaxInt64) + 1,
			wantErr: true,
		},
		{
			name:    "very large overflow",
			input:   math.MaxUint64,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SafeUint64ToInt64(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("SafeUint64ToInt64(%d) error = %v, wantErr %t", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Fatalf("SafeUint64ToInt64(%d) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}
