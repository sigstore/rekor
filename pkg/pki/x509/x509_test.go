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
	"context"
	"crypto"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/sigstore/rekor/pkg/signer"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
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
const ecdsaPriv = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmrLtCpBdXgXLUr7o
nSUPfo3oXMjmvuwTOjpTulIBKlKhRANCAATH6KSpTFe6uXFmW1qNEFXaO7fWPfZt
pPZrHZ1cFykidZoURKoYXfkohJ+U/USYy8Sd8b4DMd5xDRZCnlDM0h37
-----END PRIVATE KEY-----`

// Extracted from above with:
// openssl ec -in ec_private.pem -pubout
const ecdsaPub = `-----BEGIN PUBLIC KEY-----
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
			priv: ecdsaPriv,
			pub:  ecdsaPub,
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
			priv: ecdsaPriv,
			pub:  ecdsaPub,
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

func TestNilCertChainToPEM(t *testing.T) {
	certChain := []*x509.Certificate{}
	if _, err := CertChainToPEM(certChain); err != nil {
		t.Fatal(err)
	}
}

func TestCertChain_Verify(t *testing.T) {
	mem, err := signer.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	// A properly created cert chain should encode to PEM OK.
	ctx := context.Background()
	pk, err := mem.PublicKey(options.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	certChain, err := signer.NewTimestampingCertWithSelfSignedCA(pk)
	if err != nil {
		t.Fatal(err)
	}
	certChainBytes, err := CertChainToPEM(certChain)
	if err != nil {
		t.Fatal(err)
	}

	// Parse and verify timestamping cert chain
	parsedCertChain, err := ParseTimestampCertChain(certChainBytes)
	if err != nil {
		t.Fatal(err)
	}

	// Compare with original
	for idx, cert := range parsedCertChain {
		if !cert.Equal(certChain[idx]) {
			t.Fatal("unexpected error comparing cert chain")
		}
	}
}
