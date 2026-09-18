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

package intoto

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/go-openapi/swag/conv"
	"github.com/sigstore/rekor/pkg/generated/models"
)

// TestV002Entry_Canonicalize_PEMTrailingNewline reproduces sigstore/rekor#1170:
// when a client submits an intoto v0.0.2 entry whose embedded certificate PEM
// does NOT end with a trailing newline (a legal but non-canonical PEM
// encoding), Canonicalize() is expected to normalize it -- the same way
// hashedrekord's Canonicalize() re-derives PublicKey.Content via
// keyObj.CanonicalValue() instead of copying client-submitted bytes verbatim.
func TestV002Entry_Canonicalize_PEMTrailingNewline(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1)}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	// Canonical PEM (as Go's pem.EncodeToMemory always produces): ends with "\n".
	canonicalPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	if !bytes.HasSuffix(canonicalPEM, []byte("\n")) {
		t.Fatal("test setup invariant broken: pem.EncodeToMemory always ends with newline")
	}

	// Non-canonical variant: same cert, trailing newline stripped -- this is
	// what some client tooling produces per the bug report / maintainer's
	// 2022-11-04 reproduction.
	nonCanonicalPEM := bytes.TrimRight(canonicalPEM, "\n")
	if bytes.Equal(nonCanonicalPEM, canonicalPEM) {
		t.Fatal("test setup invariant broken: variants must differ")
	}

	validPayload := "hellothispayloadisvalid"
	dsseEnv := envelope(t, priv, []byte(validPayload))
	rekorEnv := createRekorEnvelope(dsseEnv, [][]byte{nonCanonicalPEM})

	v := &V002Entry{
		IntotoObj: models.IntotoV002Schema{
			Content: &models.IntotoV002SchemaContent{
				Envelope: rekorEnv,
				Hash: &models.IntotoV002SchemaContentHash{
					Algorithm: conv.Pointer(models.IntotoV002SchemaContentHashAlgorithmSha256),
					Value:     conv.Pointer(envelopeHash(t, dsseEnv)),
				},
			},
		},
	}

	if err := v.Unmarshal(&models.Intoto{
		APIVersion: conv.Pointer(APIVERSION),
		Spec:       v.IntotoObj,
	}); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	canonicalBytes, err := v.Canonicalize(context.Background())
	if err != nil {
		t.Fatalf("Canonicalize failed: %v", err)
	}

	var out models.Intoto
	if err := json.Unmarshal(canonicalBytes, &out); err != nil {
		t.Fatalf("could not unmarshal canonicalized entry: %v", err)
	}
	spec, ok := out.Spec.(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected spec type %T", out.Spec)
	}
	content := spec["content"].(map[string]interface{})
	envMap := content["envelope"].(map[string]interface{})
	sigs := envMap["signatures"].([]interface{})
	sig0 := sigs[0].(map[string]interface{})
	storedPubKeyB64 := sig0["publicKey"].(string)

	storedPubKey, err := base64.StdEncoding.DecodeString(storedPubKeyB64)
	if err != nil {
		t.Fatalf("could not decode stored publicKey: %v", err)
	}

	// EXPECTED (post-fix) behavior: Canonicalize should normalize to the
	// canonical PEM form (trailing newline), matching hashedrekord's
	// behavior and CreateFromArtifactProperties' own use of CanonicalValue().
	if !bytes.Equal(storedPubKey, canonicalPEM) {
		t.Errorf("Canonicalize() did not normalize PEM encoding of embedded certificate:\n"+
			"stored (len %d): %q\ncanonical (len %d): %q\n"+
			"this reproduces sigstore/rekor#1170: the client-submitted "+
			"non-canonical PEM (missing trailing newline) was stored verbatim "+
			"instead of being re-derived via x509.NewPublicKey(...).CanonicalValue()",
			len(storedPubKey), storedPubKey, len(canonicalPEM), canonicalPEM)
	}
}
