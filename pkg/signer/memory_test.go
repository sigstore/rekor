/*
Copyright The Rekor Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package signer

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

func TestMemory(t *testing.T) {
	ctx := context.Background()

	m, err := New(ctx, "memory")
	if err != nil {
		t.Fatalf("new memory: %v", err)
	}
	payload := []byte("payload")

	// sign a payload
	sig, err := m.SignMessage(bytes.NewReader(payload), options.WithContext(ctx))
	if err != nil {
		t.Fatalf("signing payload: %v", err)
	}

	// verify the signature against public key
	pubKey, err := m.PublicKey(options.WithContext(ctx))
	if err != nil {
		t.Fatalf("public key: %v", err)
	}

	verifier, err := signature.LoadVerifier(pubKey, crypto.SHA256)
	if err != nil {
		t.Fatalf("initializing verifier: %v", err)
	}

	if err := verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(payload), options.WithContext(ctx)); err != nil {
		t.Fatalf("verification failed: %v", err)
	}

	// verify signature using the cert's public key
	certChain, err := NewTimestampingCertWithSelfSignedCA(pubKey)
	if err != nil {
		t.Fatalf("generating timestamping cert: %v", err)
	}
	pkCert := certChain[0].PublicKey

	verifier, err = signature.LoadVerifier(pkCert, crypto.SHA256)
	if err != nil {
		t.Fatalf("initializing cert pub key verifier: %v", err)
	}
	if err := verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(payload), options.WithContext(ctx)); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
	// verify that the cert chain is configured for timestamping
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	for _, cert := range certChain[1:(len(certChain) - 1)] {
		intermediates.AddCert(cert)
	}
	roots.AddCert(certChain[len(certChain)-1])
	_, err = certChain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		Intermediates: intermediates,
	})
	if err != nil {
		t.Fatalf("invalid timestamping cert chain")
	}
}
