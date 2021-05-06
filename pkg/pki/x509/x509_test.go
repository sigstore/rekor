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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/sigstore/rekor/pkg/signer"
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
	// Get a private key object
	p, _ := pem.Decode([]byte(pkey))
	if p.Type != "PRIVATE KEY" {
		t.Fatalf("expected private key, found object of type %s", p.Type)
	}
	pk, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	h := sha256.Sum256(b)
	var signature []byte
	switch k := pk.(type) {
	case *rsa.PrivateKey:
		signature, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
	case *ecdsa.PrivateKey:
		signature, err = ecdsa.SignASN1(rand.Reader, k, h[:])
	case ed25519.PrivateKey:
		signature = ed25519.Sign(k, b)
	}

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

func TestCertChain_Verify(t *testing.T) {
	mem, err := signer.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	// A properly created cert chain should encode to PEM OK.
	certChainBytes, err := CertChainToPEM(mem.CertChain)
	if err != nil {
		t.Fatal(err)
	}

	// Verify bytes by comparing with the certs.
	var block *pem.Block
	block, certChainBytes = pem.Decode(certChainBytes)
	for i := 0; block != nil; block, certChainBytes = pem.Decode(certChainBytes) {
		if block.Type != "CERTIFICATE" {
			t.Fatal(err)
		}
		if !bytes.Equal(block.Bytes, mem.CertChain[i].Raw) {
			t.Fatal(err)
		}
		i++
	}

}
