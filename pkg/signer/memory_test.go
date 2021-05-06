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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"testing"
)

func TestMemory(t *testing.T) {
	ctx := context.Background()

	m, certChain, err := New(ctx, "memory")
	if err != nil {
		t.Fatalf("new memory: %v", err)
	}
	payload := []byte("payload")

	// sign a payload
	signature, _, err := m.Sign(ctx, payload)
	if err != nil {
		t.Fatalf("signing payload: %v", err)
	}

	// verify the signature against public key
	pubKey, err := m.PublicKey(ctx)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}

	pk, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("ecdsa public key: %v", err)
	}
	h := crypto.SHA256.New()
	if _, err := h.Write(payload); err != nil {
		t.Fatalf("writing payload: %v", err)
	}
	if !ecdsa.VerifyASN1(pk, h.Sum(nil), signature) {
		t.Fatalf("unable to verify signature")
	}

	// verify signature using the cert's public key
	pkCert, ok := certChain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("cert ecdsa public key: %v", err)
	}
	if !ecdsa.VerifyASN1(pkCert, h.Sum(nil), signature) {
		t.Fatalf("unable to verify signature")
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
