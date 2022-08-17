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

package api

import (
	"testing"
)

func Test_Collection(t *testing.T) {

	vals := []string{"foo", "bar", "baz", "baz", "baz"}

	t.Run("Unique", func(t *testing.T) {
		unq := NewUniq()
		unq.Add(vals)

		if len(unq.Values()) != 3 {
			t.Errorf("expected 3 unique values, got %d", len(unq.Values()))
		}
		expected := []string{"foo", "bar", "baz"}
		for i, v := range unq.Values() {
			if v != expected[i] {
				t.Errorf("expected %s, got %s", expected[i], v)
			}
		}
	})

	t.Run("Collection", func(t *testing.T) {

		uniq1 := []string{"foo", "bar", "baz"}
		uniq2 := []string{"foo", "bar", "baz"}
		uniq3 := []string{"corge", "grault", "garply", "foo"}

		t.Run("with 'and' operator", func(t *testing.T) {
			set := NewCollection("and")
			set.Add(uniq1)
			set.Add(uniq2)
			set.Add(uniq3)

			if len(set.Values()) != 1 {
				t.Errorf("expected 1 value, got %d", len(set.Values()))
			}
			expected := []string{"foo", "bar", "baz", "baz", "baz"}
			for i, v := range set.Values() {
				if v != expected[i] {
					t.Errorf("expected %s, got %s", expected[i], v)
				}
			}
		})
		t.Run("with 'or' operator", func(t *testing.T) {
			set := NewCollection("or")
			set.Add(uniq1)
			set.Add(uniq2)
			set.Add(uniq3)

			if len(set.Values()) != 6 {
				t.Errorf("expected 6 values, got %d", len(set.Values()))
			}

		})
	})

}
