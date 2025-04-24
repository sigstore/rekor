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

package signer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/fake"
	tinkUtils "github.com/sigstore/sigstore/pkg/signature/tink"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/signature"
)

func TestNewTinkCA(t *testing.T) {
	aeskh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		t.Fatalf("error creating AEAD key handle: %v", err)
	}
	a, err := aead.New(aeskh)
	if err != nil {
		t.Fatalf("error creating AEAD key: %v", err)
	}

	kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("error creating ECDSA key handle: %v", err)
	}
	khsigner, err := tinkUtils.KeyHandleToSigner(kh)
	if err != nil {
		t.Fatalf("error converting ECDSA key handle to signer: %v", err)
	}

	dir := t.TempDir()
	keysetPath := filepath.Join(dir, "keyset.json.enc")
	f, err := os.Create(keysetPath)
	if err != nil {
		t.Fatalf("error creating file: %v", err)
	}
	defer f.Close()
	jsonWriter := keyset.NewJSONWriter(f)
	if err := kh.Write(jsonWriter, a); err != nil {
		t.Fatalf("error writing enc keyset: %v", err)
	}

	signer, err := NewTinkSignerWithHandle(a, keysetPath)
	if err != nil {
		t.Fatalf("unexpected error creating signer: %v", err)
	}

	// Expect keyset signer and created signer public key match
	pubKey, err := signer.PublicKey()
	if err != nil {
		t.Fatalf("unexpected error creating signer public key: %v", err)
	}
	if err := cryptoutils.EqualKeys(pubKey, khsigner.Public()); err != nil {
		t.Fatalf("keys between CA and signer do not match: %v", err)
	}

	// Failure: Unable to decrypt keyset
	aeskhAlt, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		t.Fatalf("error creating AEAD key handle: %v", err)
	}
	aeadAlt, err := aead.New(aeskhAlt)
	if err != nil {
		t.Fatalf("error creating AEAD key: %v", err)
	}
	_, err = NewTinkSignerWithHandle(aeadAlt, keysetPath)
	if err == nil || !strings.Contains(err.Error(), "decryption failed") {
		t.Fatalf("expected error decrypting keyset, got %v", err)
	}
}
