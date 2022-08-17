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

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func Test_Collection(t *testing.T) {

	vals := []string{"foo", "bar", "baz", "baz", "baz"}

	t.Run("Unique", func(t *testing.T) {
		unq := NewUniq()
		unq.Add(vals...)

		if len(unq.Values()) != 3 {
			t.Errorf("expected 3 unique values, got %d", len(unq.Values()))
		}
		expected := []string{"foo", "bar", "baz"}
		if !testEqualNoOrder(t, expected, unq.Values()) {
			t.Errorf("expected %v, got %v", expected, unq.Values())
		}
	})

	t.Run("Collection", func(t *testing.T) {

		uniq1 := []string{"foo", "bar", "baz"}
		uniq2 := []string{"foo", "bar", "baz"}
		uniq3 := []string{"corge", "grault", "garply", "foo"}

		tests := []struct {
			name     string
			operator string
			expected []string
		}{
			{name: "with 'and' operator",
				operator: "and",
				expected: []string{"foo"},
			},
			{name: "with 'or' operator",
				operator: "or",
				expected: []string{"foo", "bar", "baz", "corge", "grault", "garply"},
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				c := NewCollection(test.operator)
				c.Add(uniq1)
				c.Add(uniq2)
				c.Add(uniq3)

				if !testEqualNoOrder(t, test.expected, c.Values()) {
					t.Errorf("expected %v, got %v", test.expected, c.Values())
				}
			})
		}

	})

}

// testEqualNoOrder compares two slices of strings without considering order.
func testEqualNoOrder(t *testing.T, expected, actual []string) bool {
	t.Helper()
	less := func(a, b string) bool { return a < b }
	return cmp.Diff(actual, expected, cmpopts.SortSlices(less)) == ""
}
