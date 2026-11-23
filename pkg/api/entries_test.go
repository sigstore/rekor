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

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/google/trillian"
	ttypes "github.com/google/trillian/types"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/entries"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/signer"
	"github.com/sigstore/rekor/pkg/types"
	_ "github.com/sigstore/rekor/pkg/types/alpine/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/cose/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/dsse/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/helm/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/intoto/v0.0.2"
	_ "github.com/sigstore/rekor/pkg/types/jar/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/rfc3161/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/rpm/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/tuf/v0.0.1"
	"github.com/spf13/viper"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestRetrieveUUIDFromTree_UnconfiguredTreeID tests that retrieveUUIDFromTree returns ErrNotFound when the tree ID is not in the configured shard set.
// This ensures that the API correctly rejects requests for tree IDs that are not configured, preventing unnecessary calls to the Trillian client manager and backend.
func TestRetrieveUUIDFromTree_UnconfiguredTreeID(t *testing.T) {
	ranges, err := sharding.NewLogRanges(context.Background(), "", 1, signer.SigningConfig{SigningSchemeOrKeyPath: "memory"})
	if err != nil {
		t.Fatalf("Failed to create LogRanges: %v", err)
	}

	api = &API{
		logRanges: ranges,
		// explicitly nil. if validation fails, using this manager will panic.
		trillianClientManager: nil,
	}

	validUUID := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	_, err = retrieveUUIDFromTree(context.Background(), validUUID, 999)

	if err != ErrNotFound {
		t.Errorf("Expected ErrNotFound, got: %v", err)
	}
}

func TestGetLogEntryByUUIDHandler_InvalidID(t *testing.T) {
	tests := map[string]string{
		"invalid tree ID": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"zero tree ID":    "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"malformed UUID":  "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
	}

	for name, invalidID := range tests {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/log/entries/"+invalidID, nil)
			params := entries.GetLogEntryByUUIDParams{
				HTTPRequest: req,
				EntryUUID:   invalidID,
			}

			responder := GetLogEntryByUUIDHandler(params)

			recorder := httptest.NewRecorder()
			responder.WriteResponse(recorder, runtime.JSONProducer())

			if recorder.Code != http.StatusBadRequest {
				t.Errorf("Expected status code %d (Bad Request), got %d", http.StatusBadRequest, recorder.Code)
			}
		})
	}
}

func TestClearProposedEntrySpec(t *testing.T) {
	dsse := &models.DSSE{Spec: map[string]any{"k": "v"}}
	intoto := &models.Intoto{Spec: map[string]any{"k": "v"}}
	hashedrekord := &models.Hashedrekord{Spec: map[string]any{"k": "v"}}

	clearProposedEntrySpec(dsse)
	clearProposedEntrySpec(intoto)
	clearProposedEntrySpec(hashedrekord)
	clearProposedEntrySpec(nil)

	if dsse.Spec != nil {
		t.Errorf("expected DSSE.Spec to be nil, got %v", dsse.Spec)
	}
	if intoto.Spec != nil {
		t.Errorf("expected Intoto.Spec to be nil, got %v", intoto.Spec)
	}
	if hashedrekord.Spec != nil {
		t.Errorf("expected Hashedrekord.Spec to be nil, got %v", hashedrekord.Spec)
	}
}

func TestLeafKindAndVersion(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantKind    string
		wantVersion string
		wantErr     bool
	}{
		{
			name:        "hashedrekord",
			input:       `{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{"data":{}}}`,
			wantKind:    "hashedrekord",
			wantVersion: "0.0.1",
		},
		{
			name:        "intoto",
			input:       `{"apiVersion":"0.0.2","kind":"intoto","spec":{}}`,
			wantKind:    "intoto",
			wantVersion: "0.0.2",
		},
		{
			name:    "missing kind",
			input:   `{"apiVersion":"0.0.1","spec":{}}`,
			wantErr: true,
		},
		{
			name:    "invalid json",
			input:   `{not-json`,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotKind, gotVersion, err := leafKindAndVersion([]byte(tc.input))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (kind=%q, version=%q)", gotKind, gotVersion)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotKind != tc.wantKind || gotVersion != tc.wantVersion {
				t.Fatalf("leafKindAndVersion() = (%q, %q), want (%q, %q)", gotKind, gotVersion, tc.wantKind, tc.wantVersion)
			}
		})
	}
}

func TestSupportsAttestation(t *testing.T) {
	// Verify all registered types match their EntryWithAttestationImpl interface.
	types.TypeMap.Range(func(k, v any) bool {
		kind := k.(string)
		typeImpl := v.(func() types.TypeImpl)()
		for _, ver := range typeImpl.SupportedVersions() {
			type versionedUnmarshaler interface {
				VersionedUnmarshal(models.ProposedEntry, string) (types.EntryImpl, error)
			}
			vu, ok := typeImpl.(versionedUnmarshaler)
			if !ok {
				t.Fatalf("type %q does not implement VersionedUnmarshal", kind)
			}
			entry, err := vu.VersionedUnmarshal(nil, ver)
			if err != nil {
				t.Fatalf("VersionedUnmarshal(%q, %q) error: %v", kind, ver, err)
			}
			_, want := entry.(types.EntryWithAttestationImpl)
			if got := types.SupportsAttestation(kind, ver); got != want {
				t.Errorf("SupportsAttestation(%q, %q) = %v, want %v", kind, ver, got, want)
			}
			// Second call exercises the cache.
			if got := types.SupportsAttestation(kind, ver); got != want {
				t.Errorf("cached SupportsAttestation(%q, %q) = %v, want %v", kind, ver, got, want)
			}
		}
		return true
	})

	// Unknown kind or version should fail safe (return true) so callers fall back
	// to full unmarshaling.
	if !types.SupportsAttestation("unknown-kind", "0.0.1") {
		t.Errorf("expected SupportsAttestation to return true for unknown kind")
	}
	if !types.SupportsAttestation("hashedrekord", "9.9.9") {
		t.Errorf("expected SupportsAttestation to return true for unknown version")
	}
}

func TestLogEntryFromLeaf_SkipsUnmarshalForNonAttestationKind(t *testing.T) {
	origEnable := viper.GetBool("enable_attestation_storage")
	viper.Set("enable_attestation_storage", true)
	t.Cleanup(func() {
		viper.Set("enable_attestation_storage", origEnable)
	})

	ranges, err := sharding.NewLogRanges(context.Background(), "", 1, signer.SigningConfig{SigningSchemeOrKeyPath: "memory"})
	if err != nil {
		t.Fatalf("NewLogRanges: %v", err)
	}

	logRoot := ttypes.LogRootV1{
		TreeSize: 1,
		RootHash: make([]byte, 32),
	}
	rootBytes, err := logRoot.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	// Intentionally omit required spec fields so that calling types.UnmarshalEntry
	// would fail; logEntryFromLeaf must succeed because hashedrekord does not
	// support attestations.
	leaf := &trillian.LogLeaf{
		LeafValue:          []byte(`{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{}}`),
		MerkleLeafHash:     make([]byte, 32),
		LeafIndex:          0,
		IntegrateTimestamp: timestamppb.New(time.Unix(1700000000, 0)),
	}
	signedLogRoot := &trillian.SignedLogRoot{LogRoot: rootBytes}
	proof := &trillian.Proof{LeafIndex: 0}

	entry, err := logEntryFromLeaf(context.Background(), leaf, signedLogRoot, proof, 1, ranges, map[int64]string{}, "rekor.example.com")
	if err != nil {
		t.Fatalf("logEntryFromLeaf returned unexpected error: %v", err)
	}
	if len(entry) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entry))
	}
}
