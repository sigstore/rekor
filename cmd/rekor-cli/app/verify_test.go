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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-openapi/swag/conv"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/transparency-dev/merkle/rfc6962"

	// register hashedrekord type for UnmarshalEntry/CanonicalizeEntry
	_ "github.com/sigstore/rekor/pkg/types/hashedrekord"
	_ "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
)

// makeEntryBody builds a base64-encoded entry body from raw bytes.
func makeEntryBody(t *testing.T, raw []byte) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(raw)
}

// leafUUID computes the UUID (hex leaf hash) for a given raw entry body.
func leafUUID(raw []byte) string {
	return hex.EncodeToString(rfc6962.DefaultHasher.HashLeaf(raw))
}

func TestVerifyBodyMatchesUUID(t *testing.T) {
	rawBody := []byte(`{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{}}`)

	correctUUID := leafUUID(rawBody)
	wrongUUID := hex.EncodeToString(rfc6962.DefaultHasher.HashLeaf([]byte("different body")))

	for _, tc := range []struct {
		name      string
		body      interface{}
		entryUUID string
		wantErr   bool
	}{
		{
			name:      "matching body and UUID",
			body:      makeEntryBody(t, rawBody),
			entryUUID: correctUUID,
			wantErr:   false,
		},
		{
			name:      "mismatched body and UUID",
			body:      makeEntryBody(t, rawBody),
			entryUUID: wrongUUID,
			wantErr:   true,
		},
		{
			name:      "body not a string",
			body:      12345,
			entryUUID: correctUUID,
			wantErr:   true,
		},
		{
			name:      "invalid base64 body",
			body:      "not-valid-base64!@#$",
			entryUUID: correctUUID,
			wantErr:   true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := models.LogEntryAnon{
				Body: tc.body,
			}
			err := verifyBodyMatchesUUID(entry, tc.entryUUID)
			if (err != nil) != tc.wantErr {
				t.Errorf("verifyBodyMatchesUUID() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// createHashedRekordProposedEntry creates a valid hashedrekord ProposedEntry
// using real ECDSA crypto, suitable for canonicalization.
func createHashedRekordProposedEntry(t *testing.T, data []byte) (models.ProposedEntry, *ecdsa.PrivateKey, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	pubBytes, err := cryptoutils.MarshalPublicKeyToPEM(key.Public())
	if err != nil {
		t.Fatalf("marshalling public key: %v", err)
	}

	signer, err := signature.LoadSigner(key, crypto.SHA256)
	if err != nil {
		t.Fatalf("loading signer: %v", err)
	}
	sigBytes, err := signer.SignMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("signing message: %v", err)
	}

	h := sha256.Sum256(data)
	dataSHA256 := hex.EncodeToString(h[:])

	entry := &models.Hashedrekord{
		Spec: models.HashedrekordV001Schema{
			Signature: &models.HashedrekordV001SchemaSignature{
				Content: sigBytes,
				PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
					Content: pubBytes,
				},
			},
			Data: &models.HashedrekordV001SchemaData{
				Hash: &models.HashedrekordV001SchemaDataHash{
					Value:     conv.Pointer(dataSHA256),
					Algorithm: conv.Pointer(models.HashedrekordV001SchemaDataHashAlgorithmSha256),
				},
			},
		},
	}
	entry.APIVersion = conv.Pointer("0.0.1")

	return entry, key, pubBytes
}

// canonicalizeProposedEntry returns the canonical bytes for a proposed entry,
// mirroring what the server does before inserting into the Merkle tree.
func canonicalizeProposedEntry(t *testing.T, pe models.ProposedEntry) []byte {
	t.Helper()
	ctx := context.Background()
	entryImpl, err := types.UnmarshalEntry(pe)
	if err != nil {
		t.Fatalf("unmarshalling entry: %v", err)
	}
	canonical, err := types.CanonicalizeEntry(ctx, entryImpl)
	if err != nil {
		t.Fatalf("canonicalizing entry: %v", err)
	}
	return canonical
}

func TestVerifyProposedEntryMatchesBody(t *testing.T) {
	data := []byte("test artifact content")
	proposedEntry, _, _ := createHashedRekordProposedEntry(t, data)

	// Get the canonical form that would be stored in the log
	canonicalBytes := canonicalizeProposedEntry(t, proposedEntry)

	// Build a different entry with different artifact content
	differentData := []byte("different artifact content")
	differentEntry, _, _ := createHashedRekordProposedEntry(t, differentData)
	differentCanonicalBytes := canonicalizeProposedEntry(t, differentEntry)

	for _, tc := range []struct {
		name          string
		proposedEntry models.ProposedEntry
		body          string // base64-encoded body in the server response
		wantErr       bool
	}{
		{
			name:          "matching entry - server returns correct body",
			proposedEntry: proposedEntry,
			body:          base64.StdEncoding.EncodeToString(canonicalBytes),
			wantErr:       false,
		},
		{
			name:          "mismatched entry - server returns different artifact's body",
			proposedEntry: proposedEntry,
			body:          base64.StdEncoding.EncodeToString(differentCanonicalBytes),
			wantErr:       true,
		},
		{
			name:          "mismatched entry - server returns arbitrary body",
			proposedEntry: proposedEntry,
			body:          base64.StdEncoding.EncodeToString([]byte(`{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{}}`)),
			wantErr:       true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := models.LogEntryAnon{
				Body: tc.body,
			}
			err := verifyProposedEntryMatchesBody(context.Background(), tc.proposedEntry, entry)
			if (err != nil) != tc.wantErr {
				t.Errorf("verifyProposedEntryMatchesBody() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestMaliciousServerSubstitution is an end-to-end scenario test that
// demonstrates the attack: a malicious server returns a valid log entry
// for a different artifact than the one the user asked about. The new
// checks must reject this.
func TestMaliciousServerSubstitution(t *testing.T) {
	// Victim creates an entry for their artifact
	victimData := []byte("victim's legitimate artifact")
	victimEntry, _, _ := createHashedRekordProposedEntry(t, victimData)
	victimCanonical := canonicalizeProposedEntry(t, victimEntry)

	// Attacker has a different artifact already in the log
	attackerData := []byte("attacker's malicious artifact")
	attackerEntry, _, _ := createHashedRekordProposedEntry(t, attackerData)
	attackerCanonical := canonicalizeProposedEntry(t, attackerEntry)
	attackerBody := base64.StdEncoding.EncodeToString(attackerCanonical)

	// The attacker's entry UUID (derived from attacker's body leaf hash)
	attackerUUID := leafUUID(attackerCanonical)

	// Scenario 1: body-UUID check catches UUID mismatch
	// Server returns attacker's body but claims victim's UUID
	t.Run("body-UUID mismatch catches substitution", func(t *testing.T) {
		victimUUID := leafUUID(victimCanonical)
		entry := models.LogEntryAnon{
			Body: attackerBody,
		}
		err := verifyBodyMatchesUUID(entry, victimUUID)
		if err == nil {
			t.Error("expected body-UUID check to catch substitution, but it passed")
		}
	})

	// Scenario 2: even if UUID matches the substituted body, the
	// proposed-entry check catches that it's a different artifact
	t.Run("proposed entry check catches substitution", func(t *testing.T) {
		entry := models.LogEntryAnon{
			Body: attackerBody,
		}
		// UUID matches the attacker body (server is internally consistent)
		err := verifyBodyMatchesUUID(entry, attackerUUID)
		if err != nil {
			t.Fatalf("body-UUID should match for attacker's own entry: %v", err)
		}
		// But the proposed entry check catches that this isn't what we asked for
		err = verifyProposedEntryMatchesBody(context.Background(), victimEntry, entry)
		if err == nil {
			t.Error("expected proposed entry check to catch substitution, but it passed")
		}
	})
}

// TestBodyMatchesUUID_WithTreeID verifies the check works when the
// entry UUID includes a tree ID prefix (full entry ID format).
func TestBodyMatchesUUID_WithTreeID(t *testing.T) {
	rawBody := []byte(`{"test":"data"}`)
	uuid := leafUUID(rawBody)

	// Simulate a full entry ID with tree ID prefix (16 hex chars tree ID + 64 hex chars UUID)
	treeIDHex := "0000000000000001"
	fullEntryID := treeIDHex + uuid

	entry := models.LogEntryAnon{
		Body: makeEntryBody(t, rawBody),
	}
	err := verifyBodyMatchesUUID(entry, fullEntryID)
	if err != nil {
		t.Errorf("verifyBodyMatchesUUID() with tree ID prefix: unexpected error: %v", err)
	}
}

// createDifferentKeyProposedEntry builds a hashedrekord for the same data
// but signed with a different key, producing a different canonical entry.
func createDifferentKeyProposedEntry(t *testing.T, data []byte) models.ProposedEntry {
	t.Helper()
	pe, _, _ := createHashedRekordProposedEntry(t, data)
	return pe
}

// TestProposedEntryMatch_SameDataDifferentKey verifies that entries for
// the same artifact data but signed with different keys are detected as
// different (they canonicalize to different leaf hashes because the public
// key is part of the canonical form).
func TestProposedEntryMatch_SameDataDifferentKey(t *testing.T) {
	data := []byte("same artifact data")

	entry1, _, _ := createHashedRekordProposedEntry(t, data)
	entry2 := createDifferentKeyProposedEntry(t, data)

	canonical1 := canonicalizeProposedEntry(t, entry1)
	canonical2 := canonicalizeProposedEntry(t, entry2)

	// Sanity check: same data but different keys should produce different canonical forms
	if bytes.Equal(canonical1, canonical2) {
		t.Fatal("expected different canonical forms for different keys, but they matched")
	}

	// entry1 asks to verify, server returns entry2's body
	serverResponse := models.LogEntryAnon{
		Body: base64.StdEncoding.EncodeToString(canonical2),
	}
	err := verifyProposedEntryMatchesBody(context.Background(), entry1, serverResponse)
	if err == nil {
		t.Error("expected mismatch when server returns entry for same data but different key")
	}
}

// makeHRCanonicalJSON constructs a hashedrekord canonical JSON entry directly,
// bypassing crypto validation — useful for building arbitrary body content
// for body-UUID tests without needing real keys.
func makeHRCanonicalJSON(t *testing.T, hash, algo string, sigContent, pubKeyContent []byte) []byte {
	t.Helper()
	obj := map[string]any{
		"apiVersion": "0.0.1",
		"kind":       "hashedrekord",
		"spec": map[string]any{
			"data": map[string]any{
				"hash": map[string]any{
					"algorithm": algo,
					"value":     hash,
				},
			},
			"signature": map[string]any{
				"content": base64.StdEncoding.EncodeToString(sigContent),
				"publicKey": map[string]any{
					"content": base64.StdEncoding.EncodeToString(pubKeyContent),
				},
			},
		},
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshalling JSON: %v", err)
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		t.Fatalf("canonicalizing JSON: %v", err)
	}
	return canonical
}

// TestBodyMatchesUUID_AttackerControlledUUID verifies that the body-UUID
// check binds them together, so if a user requests --uuid and the server
// returns a body that doesn't match, it is caught.
func TestBodyMatchesUUID_AttackerControlledUUID(t *testing.T) {
	// Attacker's body
	attackerBody := makeHRCanonicalJSON(t,
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"sha256",
		[]byte("attacker-sig"),
		[]byte("attacker-key"),
	)

	// Victim's body
	victimBody := makeHRCanonicalJSON(t,
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"sha256",
		[]byte("victim-sig"),
		[]byte("victim-key"),
	)

	victimUUID := leafUUID(victimBody)

	// Server returns attacker's body but with victim's UUID
	entry := models.LogEntryAnon{
		Body: base64.StdEncoding.EncodeToString(attackerBody),
	}
	err := verifyBodyMatchesUUID(entry, victimUUID)
	if err == nil {
		t.Error("expected body-UUID mismatch to be detected")
	}

	// Server returns attacker's body with matching UUID — internally consistent
	attackerUUID := leafUUID(attackerBody)
	err = verifyBodyMatchesUUID(entry, attackerUUID)
	if err != nil {
		t.Errorf("expected consistent attacker entry to pass body-UUID check: %v", err)
	}
}
