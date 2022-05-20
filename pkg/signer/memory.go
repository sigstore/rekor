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
	"crypto"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/sigstore/sigstore/pkg/signature"
)

const MemoryScheme = "memory"

// returns an in-memory signer and verify, used for spinning up local instances
type Memory struct {
	signature.ECDSASignerVerifier
}

func NewMemory() (*Memory, error) {
	// generate a keypair
	sv, _, err := signature.NewECDSASignerVerifier(elliptic.P256(), rand.Reader, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return &Memory{
		ECDSASignerVerifier: *sv,
	}, nil
}
