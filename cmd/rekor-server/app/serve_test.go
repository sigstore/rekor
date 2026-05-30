//
// Copyright 2026 The Sigstore Authors.
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
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestFilterEntryTypes_EmptyRequestedReturnsNothing(t *testing.T) {
	t.Parallel()
	allEntries := map[string][]string{
		"rekord":       {"0.0.1"},
		"intoto":       {"0.0.1", "0.0.2"},
		"hashedrekord": {"0.0.1"},
	}

	got, err := filterEntryTypes(allEntries, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("nil requested should return no entries")
	}

	got, err = filterEntryTypes(allEntries, []string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty slice requested should return no entries")
	}
}

func TestFilterEntryTypes_SubsetPreservesVersions(t *testing.T) {
	t.Parallel()
	allEntries := map[string][]string{
		"rekord":       {"0.0.1"},
		"intoto":       {"0.0.1", "0.0.2"},
		"hashedrekord": {"0.0.1"},
	}

	got, err := filterEntryTypes(allEntries, []string{"rekord", "intoto"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{"rekord", "intoto"}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("subset filter mismatch\n got: %v\nwant: %v", got, want)
	}
}

func TestFilterEntryTypes_UnknownKindErrors(t *testing.T) {
	t.Parallel()
	allEntries := map[string][]string{
		"rekord": {"0.0.1"},
		"intoto": {"0.0.1", "0.0.2"},
	}

	_, err := filterEntryTypes(allEntries, []string{"rekord", "doesnotexist"})
	if err == nil {
		t.Fatal("expected error for unknown kind, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, `"doesnotexist"`) {
		t.Errorf("error should quote the bad kind, got: %v", err)
	}
	for _, want := range []string{"rekord", "intoto"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error should list known kind %q, got: %v", want, err)
		}
	}
}

func TestFilterEntryTypes_KnownKindsListedSorted(t *testing.T) {
	t.Parallel()
	allEntries := map[string][]string{
		"zeta":  {"0.0.1"},
		"alpha": {"0.0.1"},
		"mu":    {"0.0.1"},
	}

	_, err := filterEntryTypes(allEntries, []string{"bogus"})
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	a, m, z := strings.Index(msg, "alpha"), strings.Index(msg, "mu"), strings.Index(msg, "zeta")
	if a == -1 || m == -1 || z == -1 {
		t.Fatalf("error message missing kinds: %s", msg)
	}
	if a >= m || m >= z {
		t.Errorf("expected sorted order alpha < mu < zeta in error, got: %s", msg)
	}
}

func TestFilterEntryTypes_DuplicatesAreIdempotent(t *testing.T) {
	t.Parallel()
	allEntries := map[string][]string{
		"rekord": {"0.0.1"},
		"intoto": {"0.0.1", "0.0.2"},
	}

	got, err := filterEntryTypes(allEntries, []string{"rekord", "rekord", "intoto"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"rekord", "intoto"}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("duplicate kinds should de-dupe\n got: %v\nwant: %v", got, want)
	}
}
