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
//

package models

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/go-openapi/runtime"
)

// TestUnmarshalProposedEntry_KnownKinds verifies that every registered kind
// unmarshals into the correct concrete type with kind/apiVersion/spec preserved.
func TestUnmarshalProposedEntry_KnownKinds(t *testing.T) {
	apiVersion := "0.0.1"
	spec := map[string]any{"data": "value"}

	cases := []struct {
		kind    string
		wantPtr any
	}{
		{"alpine", (*Alpine)(nil)},
		{"cose", (*Cose)(nil)},
		{"dsse", (*DSSE)(nil)},
		{"hashedrekord", (*Hashedrekord)(nil)},
		{"helm", (*Helm)(nil)},
		{"intoto", (*Intoto)(nil)},
		{"jar", (*Jar)(nil)},
		{"rekord", (*Rekord)(nil)},
		{"rfc3161", (*Rfc3161)(nil)},
		{"rpm", (*Rpm)(nil)},
		{"tuf", (*TUF)(nil)},
	}

	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			body := mustMarshal(t, map[string]any{
				"kind":       tc.kind,
				"apiVersion": apiVersion,
				"spec":       spec,
			})

			pe, err := UnmarshalProposedEntry(bytes.NewReader(body), runtime.JSONConsumer())
			if err != nil {
				t.Fatalf("UnmarshalProposedEntry: %v", err)
			}
			if pe.Kind() != tc.kind {
				t.Errorf("Kind() = %q, want %q", pe.Kind(), tc.kind)
			}
			if got, want := reflect.TypeOf(pe), reflect.TypeOf(tc.wantPtr); got != want {
				t.Errorf("concrete type = %v, want %v", got, want)
			}

			// apiVersion + spec should round-trip via reflection since every
			// concrete kind has APIVersion *string and Spec any fields.
			gotAPI := reflect.ValueOf(pe).Elem().FieldByName("APIVersion")
			if gotAPI.IsNil() || gotAPI.Elem().String() != apiVersion {
				t.Errorf("APIVersion = %v, want %q", gotAPI, apiVersion)
			}
			gotSpec := reflect.ValueOf(pe).Elem().FieldByName("Spec")
			if !gotSpec.IsValid() || gotSpec.IsZero() {
				t.Errorf("Spec is zero/invalid")
			}
		})
	}
}

// TestUnmarshalProposedEntry_ProposedEntryKind covers the "ProposedEntry"
// discriminator case, which returns the private base type and discards spec.
func TestUnmarshalProposedEntry_ProposedEntryKind(t *testing.T) {
	body := mustMarshal(t, map[string]any{
		"kind":       "ProposedEntry",
		"apiVersion": "0.0.1",
		"spec":       map[string]any{"ignored": true},
	})
	pe, err := UnmarshalProposedEntry(bytes.NewReader(body), runtime.JSONConsumer())
	if err != nil {
		t.Fatalf("UnmarshalProposedEntry: %v", err)
	}
	if pe.Kind() != "ProposedEntry" {
		t.Errorf("Kind() = %q, want %q", pe.Kind(), "ProposedEntry")
	}
}

// TestUnmarshalProposedEntry_EquivalenceWithGeneratedUnmarshal proves the fast
// path returns semantically identical values to invoking the per-kind
// generated UnmarshalJSON directly. This is the invariant that lets the fast
// path bypass the two-pass consumer decode.
func TestUnmarshalProposedEntry_EquivalenceWithGeneratedUnmarshal(t *testing.T) {
	cases := []struct {
		name string
		body []byte
		fn   func([]byte) (kind string, apiVersion *string, spec any, err error)
	}{
		{
			name: "dsse",
			body: realDSSEBody,
			fn: func(body []byte) (string, *string, any, error) {
				var old DSSE
				err := json.Unmarshal(body, &old)
				return old.Kind(), old.APIVersion, old.Spec, err
			},
		},
		{
			name: "hashedrekord",
			body: realHashedRekordBody,
			fn: func(body []byte) (string, *string, any, error) {
				var old Hashedrekord
				err := json.Unmarshal(body, &old)
				return old.Kind(), old.APIVersion, old.Spec, err
			},
		},
		{
			name: "intoto",
			body: realIntotoBody,
			fn: func(body []byte) (string, *string, any, error) {
				var old Intoto
				err := json.Unmarshal(body, &old)
				return old.Kind(), old.APIVersion, old.Spec, err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Fast path via UnmarshalProposedEntry.
			pe, err := UnmarshalProposedEntry(bytes.NewReader(tc.body), runtime.JSONConsumer())
			if err != nil {
				t.Fatalf("fast path: %v", err)
			}

			// Old path via json.Unmarshal directly into the concrete generated
			// type; this invokes the per-kind UnmarshalJSON method.
			oldKind, oldAPI, oldSpec, err := tc.fn(tc.body)
			if err != nil {
				t.Fatalf("old path: %v", err)
			}

			if pe.Kind() != oldKind {
				t.Errorf("Kind mismatch: fast=%q old=%q", pe.Kind(), oldKind)
			}

			newAPI := reflect.ValueOf(pe).Elem().FieldByName("APIVersion").Interface().(*string)
			if !equalStringPtr(newAPI, oldAPI) {
				t.Errorf("APIVersion mismatch: fast=%v old=%v", derefStr(newAPI), derefStr(oldAPI))
			}

			newSpec := reflect.ValueOf(pe).Elem().FieldByName("Spec").Interface()
			// Both paths run UseNumber() so nested numerics are json.Number.
			// Both DSSESchema/HashedrekordSchema/IntotoSchema are `type X any`
			// so old and new Spec should be DeepEqual map[string]any trees.
			if !reflect.DeepEqual(newSpec, oldSpec) {
				t.Errorf("Spec mismatch\n fast: %#v\n  old: %#v", newSpec, oldSpec)
			}
		})
	}
}

// TestUnmarshalProposedEntry_PreservesJSONNumber asserts UseNumber semantics
// are preserved so downstream mapstructure decode sees json.Number, matching
// the old per-kind UnmarshalJSON behavior.
func TestUnmarshalProposedEntry_PreservesJSONNumber(t *testing.T) {
	body := mustMarshal(t, map[string]any{
		"kind":       "hashedrekord",
		"apiVersion": "0.0.1",
		"spec": map[string]any{
			"nested": map[string]any{"count": 42},
		},
	})
	pe, err := UnmarshalProposedEntry(bytes.NewReader(body), runtime.JSONConsumer())
	if err != nil {
		t.Fatalf("UnmarshalProposedEntry: %v", err)
	}
	spec := pe.(*Hashedrekord).Spec.(map[string]any)
	nested := spec["nested"].(map[string]any)
	if _, ok := nested["count"].(json.Number); !ok {
		t.Errorf("nested count = %T, want json.Number", nested["count"])
	}
}

func TestUnmarshalProposedEntry_UnknownKind(t *testing.T) {
	body := mustMarshal(t, map[string]any{
		"kind":       "no-such-kind",
		"apiVersion": "0.0.1",
		"spec":       map[string]any{},
	})
	pe, err := UnmarshalProposedEntry(bytes.NewReader(body), runtime.JSONConsumer())
	if err == nil {
		t.Fatalf("expected error, got %#v", pe)
	}
	if !strings.Contains(err.Error(), "no-such-kind") {
		t.Errorf("error should mention offending kind, got %q", err.Error())
	}
}

func TestUnmarshalProposedEntry_MissingKind(t *testing.T) {
	body := mustMarshal(t, map[string]any{
		"apiVersion": "0.0.1",
		"spec":       map[string]any{},
	})
	if _, err := UnmarshalProposedEntry(bytes.NewReader(body), runtime.JSONConsumer()); err == nil {
		t.Fatal("expected error for missing kind, got nil")
	}
}

func TestUnmarshalProposedEntry_MalformedJSON(t *testing.T) {
	body := []byte(`{"kind": "dsse", "apiVersion":`)
	if _, err := UnmarshalProposedEntry(bytes.NewReader(body), runtime.JSONConsumer()); err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

// TestUnmarshalProposedEntrySlice covers the batched entry-point path.
func TestUnmarshalProposedEntrySlice(t *testing.T) {
	entries := []map[string]any{
		{"kind": "dsse", "apiVersion": "0.0.1", "spec": map[string]any{"a": 1}},
		{"kind": "intoto", "apiVersion": "0.0.1", "spec": map[string]any{"b": 2}},
	}
	body := mustMarshal(t, entries)

	got, err := UnmarshalProposedEntrySlice(bytes.NewReader(body), runtime.JSONConsumer())
	if err != nil {
		t.Fatalf("UnmarshalProposedEntrySlice: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	if got[0].Kind() != "dsse" || got[1].Kind() != "intoto" {
		t.Errorf("unexpected kinds: %q, %q", got[0].Kind(), got[1].Kind())
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func equalStringPtr(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func derefStr(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}
