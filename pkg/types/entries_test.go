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

package types

import (
	"context"
	"strings"
	"testing"

	"github.com/go-openapi/strfmt"

	"github.com/sigstore/rekor/pkg/generated/models"
	pkitypes "github.com/sigstore/rekor/pkg/pki/pkitypes"
)

func TestIsKindAllowedForSubmission_NilAllowsNone(t *testing.T) {
	SetAllowedKindsForSubmission(nil)
	for _, kind := range []string{"rekord", "intoto", "anything-at-all", ""} {
		if isKindAllowedForSubmission(kind) {
			t.Errorf("with no allowlist configured, kind %q should not be allowed", kind)
		}
	}
}

func TestIsKindAllowedForSubmission_EmptySliceAllowsNone(t *testing.T) {
	SetAllowedKindsForSubmission([]string{})
	for _, kind := range []string{"rekord", "intoto", "anything-at-all", ""} {
		if isKindAllowedForSubmission(kind) {
			t.Errorf("with no allowlist configured, kind %q should not be allowed", kind)
		}
	}
}

func TestIsKindAllowedForSubmission_RestrictsToConfiguredSet(t *testing.T) {
	SetAllowedKindsForSubmission([]string{"rekord", "intoto"})
	if !isKindAllowedForSubmission("rekord") {
		t.Error("rekord should be allowed")
	}
	if !isKindAllowedForSubmission("intoto") {
		t.Error("intoto should be allowed")
	}
	if isKindAllowedForSubmission("hashedrekord") {
		t.Error("hashedrekord should NOT be allowed")
	}
}

const fakeKind = "test-fake-kind"

type fakeProposedEntry struct{}

func (fakeProposedEntry) Kind() string                                               { return fakeKind }
func (fakeProposedEntry) SetKind(string)                                             {}
func (fakeProposedEntry) Validate(_ strfmt.Registry) error                           { return nil }
func (fakeProposedEntry) ContextValidate(_ context.Context, _ strfmt.Registry) error { return nil }

type fakeType struct{}

func (fakeType) CreateProposedEntry(_ context.Context, _ string, _ ArtifactProperties) (models.ProposedEntry, error) {
	return fakeProposedEntry{}, nil
}
func (fakeType) DefaultVersion() string           { return "0.0.1" }
func (fakeType) SupportedVersions() []string      { return []string{"0.0.1"} }
func (fakeType) IsSupportedVersion(v string) bool { return v == "0.0.1" }
func (fakeType) UnmarshalEntry(_ models.ProposedEntry) (EntryImpl, error) {
	return fakeEntryImpl{}, nil
}

type fakeEntryImpl struct{}

func (fakeEntryImpl) APIVersion() string           { return "0.0.1" }
func (fakeEntryImpl) IndexKeys() ([]string, error) { return nil, nil }
func (fakeEntryImpl) Canonicalize(_ context.Context) ([]byte, error) {
	return []byte(`{}`), nil
}
func (fakeEntryImpl) Unmarshal(_ models.ProposedEntry) error { return nil }
func (fakeEntryImpl) CreateFromArtifactProperties(_ context.Context, _ ArtifactProperties) (models.ProposedEntry, error) {
	return fakeProposedEntry{}, nil
}
func (fakeEntryImpl) Verifiers() ([]pkitypes.PublicKey, error) { return nil, nil }
func (fakeEntryImpl) ArtifactHash() (string, error)            { return "sha256:00", nil }
func (fakeEntryImpl) Insertable() (bool, error)                { return true, nil }

func registerFakeType(t *testing.T) {
	t.Helper()
	TypeMap.Store(fakeKind, func() TypeImpl { return fakeType{} })
	t.Cleanup(func() { TypeMap.Delete(fakeKind) })
}

func TestCreateVersionedEntry_DoesNotAllowWhenAllowlistUnset(t *testing.T) {
	registerFakeType(t)
	SetAllowedKindsForSubmission(nil)

	_, err := CreateVersionedEntry(fakeProposedEntry{})
	if err == nil {
		t.Fatal("expected submission to be rejected when kind is not allowlisted")
	}
	if !strings.Contains(err.Error(), "not enabled for submission") {
		t.Errorf("error should clearly attribute rejection to the allowlist, got: %v", err)
	}
	if !strings.Contains(err.Error(), fakeKind) {
		t.Errorf("error should name the rejected kind, got: %v", err)
	}
}

func TestCreateVersionedEntry_AllowsWhenKindInAllowlist(t *testing.T) {
	registerFakeType(t)
	SetAllowedKindsForSubmission([]string{fakeKind})

	if _, err := CreateVersionedEntry(fakeProposedEntry{}); err != nil {
		t.Errorf("expected submission to succeed when kind is allowlisted, got: %v", err)
	}
}

func TestCreateVersionedEntry_RejectsWhenKindNotInAllowlist(t *testing.T) {
	registerFakeType(t)
	SetAllowedKindsForSubmission([]string{"some-other-kind"})

	_, err := CreateVersionedEntry(fakeProposedEntry{})
	if err == nil {
		t.Fatal("expected submission to be rejected when kind is not allowlisted")
	}
	if !strings.Contains(err.Error(), "not enabled for submission") {
		t.Errorf("error should clearly attribute rejection to the allowlist, got: %v", err)
	}
	if !strings.Contains(err.Error(), fakeKind) {
		t.Errorf("error should name the rejected kind, got: %v", err)
	}
}

func TestUnmarshalEntry_DoesNotApplyToReadPath(t *testing.T) {
	registerFakeType(t)
	SetAllowedKindsForSubmission([]string{fakeKind})
	if _, err := UnmarshalEntry(fakeProposedEntry{}); err != nil {
		t.Errorf("UnmarshalEntry must remain unaffected by submission allowlist; got: %v", err)
	}
}
