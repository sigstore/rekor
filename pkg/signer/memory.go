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
	"crypto/elliptic"
	"crypto/rand"

	"github.com/pkg/errors"
	"github.com/sigstore/sigstore/pkg/signature"
)

const MemoryScheme = "memory"

// returns an in-memory signer and verify, used for spinning up local instances
type memory struct {
	signature.ECDSASignerVerifier
}

func NewMemory() (*memory, error) {
	// generate a keypair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "generating private key")
	}
	return &memory{
		ECDSASignerVerifier: signature.NewECDSASignerVerifier(privKey, crypto.SHA256),
	}, nil
}

func (m *memory) Sign(ctx context.Context, rawPayload []byte) ([]byte, []byte, error) {
	return m.ECDSASignerVerifier.Sign(ctx, rawPayload)
}

func (m *memory) PublicKey(ctx context.Context) (crypto.PublicKey, error) {
	return m.ECDSASignerVerifier.PublicKey(ctx)
}
