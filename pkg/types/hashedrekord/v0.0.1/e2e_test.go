//
// Copyright 2024 The Sigstore Authors.
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

//go:build e2e

package hashedrekord

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

func rekorServer() string {
	if s := os.Getenv("REKOR_SERVER"); s != "" {
		return s
	}
	return "http://localhost:3000"
}

// TestSHA256HashedRekordEntry tests sending a valid HashedRekord proposed entry.
func TestSHA256HashedRekordEntry(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("error generating key: %v", err)
	}
	pubBytes, err := cryptoutils.MarshalPublicKeyToPEM(privKey.Public())
	if err != nil {
		t.Fatalf("error marshaling public key: %v", err)
	}

	data := []byte("data")
	signer, err := signature.LoadSigner(privKey, crypto.SHA256)
	if err != nil {
		t.Fatalf("error loading verifier: %v", err)
	}
	signature, err := signer.SignMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("error signing message: %v", err)
	}

	ap := types.ArtifactProperties{
		ArtifactBytes:  []byte("data"),
		ArtifactHash:   "sha256:3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7",
		PublicKeyBytes: [][]byte{pubBytes},
		PKIFormat:      "x509",
		SignatureBytes: signature,
	}

	ei := NewEntry()

	entry, err := ei.CreateFromArtifactProperties(context.Background(), ap)
	if err != nil {
		t.Fatalf("error creating entry: %v", err)
	}

	rc, err := client.GetRekorClient(rekorServer())
	if err != nil {
		t.Errorf("error getting client: %v", err)
	}

	params := &entries.CreateLogEntryParams{}
	params.SetProposedEntry(entry)
	params.SetContext(context.Background())
	params.SetTimeout(5 * time.Second)

	if _, err = rc.Entries.CreateLogEntry(params); err != nil {
		t.Fatalf("expected no errors when submitting hashedrekord entry with sha256 to rekor %s", err)
	}
}
