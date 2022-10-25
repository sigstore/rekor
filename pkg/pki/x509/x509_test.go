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

package x509

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/sigstore/rekor/pkg/pki/x509/testutils"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// Generated with:
// openssl genrsa -out myprivate.pem 512
// openssl pkcs8 -topk8 -in myprivate.pem  -nocrypt'
const pkcs1v15Priv = `-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAoLEL57Kd5w8b5LCl
SM+5mJbVYj4GoFXP/Gynfk6mDj7aANYWAkU74xkjz0BX2Nq0IT9DyxWI8aXZ8B6R
YtbsPwIDAQABAkA2WgwTz5eXKsYdgR421YQKN6JvO1mUa9IQqFOy5jlGgbR+W5HG
JfQVJKhCGMYYmByHgR0QDk/6gvJjhuszTHuJAiEA0siY/vE20zC1UHpPgDXXVSNN
dKtM6YKBKSo47oTKQHsCIQDDKZgal50Cd3W+lOWpNO23QGZgBhJrJ70TpcPWGEsS
DQIhAIDIMLnq1G1Z4B2IbRRPUP3icMtscbRlmNZ2xovsM8oLAiBluZh+w+gjEQFe
hV3wBJajnf2+r2uKTvxO8WhSf/chQQIhAKzYjX2chfvPN6hRqeGeoPpRLXS8cdxC
A4hZJRvZgkO3
-----END PRIVATE KEY-----`

// Extracted from above with:
// openssl rsa -in myprivate.pem -pubout
const pkcs1v15Pub = `-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKCxC+eynecPG+SwpUjPuZiW1WI+BqBV
z/xsp35Opg4+2gDWFgJFO+MZI89AV9jatCE/Q8sViPGl2fAekWLW7D8CAwEAAQ==
-----END PUBLIC KEY-----`

// Generated with:
// openssl ecparam -genkey -name prime256v1 > ec_private.pem
// openssl pkcs8 -topk8 -in ec_private.pem  -nocrypt
const priv = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmrLtCpBdXgXLUr7o
nSUPfo3oXMjmvuwTOjpTulIBKlKhRANCAATH6KSpTFe6uXFmW1qNEFXaO7fWPfZt
pPZrHZ1cFykidZoURKoYXfkohJ+U/USYy8Sd8b4DMd5xDRZCnlDM0h37
-----END PRIVATE KEY-----`

// Extracted from above with:
// openssl ec -in ec_private.pem -pubout
const pub = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEx+ikqUxXurlxZltajRBV2ju31j32
baT2ax2dXBcpInWaFESqGF35KISflP1EmMvEnfG+AzHecQ0WQp5QzNId+w==
-----END PUBLIC KEY-----`

// Generated with:
// openssl genpkey -algorithm ED25519 -out edprivate.pem
const ed25519Priv = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKjlXfR/VFvO9qM9+CG2qbuSM54k8ciKWHhgNwKTgqpG
-----END PRIVATE KEY-----`

// Extracted from above with:
// openssl pkey -in edprivate.pem -pubout
const ed25519Pub = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAizWek2gKgMM+bad4rVJ5nc9NsbNOba0A0BNfzOgklRs=
-----END PUBLIC KEY-----`

func signData(t *testing.T, b []byte, pkey string) []byte {

	priv, err := cryptoutils.UnmarshalPEMToPrivateKey([]byte(pkey), cryptoutils.SkipPassword)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signature.LoadSigner(priv, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	signature, err := signer.SignMessage(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

func TestSignature_Verify(t *testing.T) {
	tests := []struct {
		name string
		priv string
		pub  string
	}{
		{
			name: "rsa",
			priv: pkcs1v15Priv,
			pub:  pkcs1v15Pub,
		},
		{
			name: "ec",
			priv: priv,
			pub:  pub,
		},
		{
			name: "ed25519",
			priv: ed25519Priv,
			pub:  ed25519Pub,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := []byte("hey! this is my test data")
			sigBytes := signData(t, data, tt.priv)
			s, err := NewSignature(bytes.NewReader(sigBytes))
			if err != nil {
				t.Fatal(err)
			}

			pub, err := NewPublicKey(strings.NewReader(tt.pub))
			if err != nil {
				t.Fatal(err)
			}

			if err := s.Verify(bytes.NewReader(data), pub); err != nil {
				t.Errorf("Signature.Verify() error = %v", err)
			}

			// Now try with the canonical value
			cb, err := s.CanonicalValue()
			if err != nil {
				t.Error(err)
			}
			canonicalSig, err := NewSignature(bytes.NewReader(cb))
			if err != nil {
				t.Error(err)
			}
			if err := canonicalSig.Verify(bytes.NewReader(data), pub); err != nil {
				t.Errorf("Signature.Verify() error = %v", err)
			}
		})
	}
}

func TestSignature_VerifyFail(t *testing.T) {
	tests := []struct {
		name string
		priv string
		pub  string
	}{
		{
			name: "rsa",
			priv: pkcs1v15Priv,
			pub:  pkcs1v15Pub,
		},
		{
			name: "ec",
			priv: priv,
			pub:  pub,
		},
		{
			name: "ed25519",
			priv: ed25519Priv,
			pub:  ed25519Pub,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make some fake data, and tamper with the signature
			data := []byte("hey! this is my test data")
			sigBytes := signData(t, data, tt.priv)
			sigBytes[0]--
			s, err := NewSignature(bytes.NewReader(sigBytes))
			if err != nil {
				t.Fatal(err)
			}

			pub, err := NewPublicKey(strings.NewReader(tt.pub))
			if err != nil {
				t.Fatal(err)
			}

			if err := s.Verify(bytes.NewReader(data), pub); err == nil {
				t.Error("Signature.Verify() expected error!")
			}
		})
	}
}

func TestPublicKeyWithCertChain(t *testing.T) {
	rootCert, rootKey, _ := testutils.GenerateRootCa()
	subCert, subKey, _ := testutils.GenerateSubordinateCa(rootCert, rootKey)
	url, _ := url.Parse("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.1.1")
	leafCert, leafKey, _ := testutils.GenerateLeafCert("subject@example.com", "oidc-issuer", url, subCert, subKey)

	pemCertChain, err := cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{leafCert, subCert, rootCert})
	if err != nil {
		t.Fatalf("unexpected error marshalling certificate chain: %v", err)
	}

	pub, err := NewPublicKey(bytes.NewReader(pemCertChain))
	if err != nil {
		t.Fatalf("unexpected error generating public key: %v", err)
	}
	if pub.certs == nil || !pub.certs[0].Equal(leafCert) || !pub.certs[1].Equal(subCert) || !pub.certs[2].Equal(rootCert) {
		t.Fatal("expected certificate chain to match provided certificate chain")
	}

	if !pub.CryptoPubKey().(*ecdsa.PublicKey).Equal(leafKey.Public()) {
		t.Fatal("expected public keys to match")
	}

	if !reflect.DeepEqual(pub.EmailAddresses(), leafCert.EmailAddresses) {
		t.Fatalf("expected matching subjects, expected %v, got %v", leafCert.EmailAddresses, pub.EmailAddresses())
	}

	expectedSubjects := leafCert.EmailAddresses
	expectedSubjects = append(expectedSubjects, leafCert.URIs[0].String())
	if !reflect.DeepEqual(pub.Subjects(), expectedSubjects) {
		t.Fatalf("expected matching subjects, expected %v, got %v", expectedSubjects, pub.Subjects())
	}

	canonicalValue, err := pub.CanonicalValue()
	if err != nil {
		t.Fatalf("unexpected error fetching canonical value: %v", err)
	}
	if !reflect.DeepEqual(canonicalValue, pemCertChain) {
		t.Fatalf("expected canonical value %v, got %v", pemCertChain, canonicalValue)
	}

	// Generate signature to verify
	data := []byte("test")
	signer, err := signature.LoadSigner(leafKey, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	sigBytes, err := signer.SignMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSignature(bytes.NewReader(sigBytes))
	if err != nil {
		t.Fatalf("unexpected error generating signature: %v", err)
	}
	err = s.Verify(bytes.NewReader(data), pub)
	if err != nil {
		t.Fatalf("unexpected error verifying signature, %v", err)
	}

	// Verify works with expired certificate
	leafCert, leafKey, _ = testutils.GenerateExpiredLeafCert("subject@example.com", "oidc-issuer", subCert, subKey)
	pemCertChain, _ = cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{leafCert, subCert, rootCert})
	pub, _ = NewPublicKey(bytes.NewReader(pemCertChain))
	signer, _ = signature.LoadSigner(leafKey, crypto.SHA256)
	sigBytes, _ = signer.SignMessage(bytes.NewReader(data))
	s, _ = NewSignature(bytes.NewReader(sigBytes))
	err = s.Verify(bytes.NewReader(data), pub)
	if err != nil {
		t.Fatalf("unexpected error verifying signature with expired certificate: %v", err)
	}

	// Verify error with invalid chain
	pemCertChain, _ = cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{leafCert, rootCert})
	pub, _ = NewPublicKey(bytes.NewReader(pemCertChain))
	signer, _ = signature.LoadSigner(leafKey, crypto.SHA256)
	sigBytes, _ = signer.SignMessage(bytes.NewReader(data))
	s, _ = NewSignature(bytes.NewReader(sigBytes))
	err = s.Verify(bytes.NewReader(data), pub)
	if err == nil || !strings.Contains(err.Error(), "x509: certificate signed by unknown authority") {
		t.Fatalf("expected error verifying signature, got %v", err)
	}

	// Verify works with chain without intermediate
	leafCert, leafKey, _ = testutils.GenerateLeafCert("subject@example.com", "oidc-issuer", nil, rootCert, rootKey)
	pemCertChain, _ = cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{leafCert, rootCert})
	pub, _ = NewPublicKey(bytes.NewReader(pemCertChain))
	signer, _ = signature.LoadSigner(leafKey, crypto.SHA256)
	sigBytes, _ = signer.SignMessage(bytes.NewReader(data))
	s, _ = NewSignature(bytes.NewReader(sigBytes))
	err = s.Verify(bytes.NewReader(data), pub)
	if err != nil {
		t.Fatalf("unexpected error verifying signature, %v", err)
	}

	// Verify error with long chain
	chain := []*x509.Certificate{}
	for i := 0; i < 11; i++ {
		chain = append(chain, leafCert)
	}
	pemCertChain, _ = cryptoutils.MarshalCertificatesToPEM(chain)
	_, err = NewPublicKey(bytes.NewReader(pemCertChain))
	if err == nil || !strings.Contains(err.Error(), "too many certificates specified in PEM block") {
		t.Fatalf("expected error with long certificate chain, got %v", err)
	}
}
