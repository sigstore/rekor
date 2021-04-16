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

package verify

import (
	"crypto"
	"crypto/ecdsa"
	"fmt"

	"github.com/google/trillian/types"
	"github.com/pkg/errors"
)

// this verification copied from https://github.com/google/trillian/blob/v1.3.13/crypto/verifier.go
// which has since been deleted

// SignedLogRoot verifies the signed log root and returns its contents
func SignedLogRoot(pub crypto.PublicKey, logRoot, logRootSignature []byte) (*types.LogRootV1, error) {
	hash := crypto.SHA256
	if err := verify(pub, hash, logRoot, logRootSignature); err != nil {
		return nil, err
	}

	var lr types.LogRootV1
	if err := lr.UnmarshalBinary(logRoot); err != nil {
		return nil, err
	}
	return &lr, nil
}

// verify cryptographically verifies the output of Signer.
func verify(pub crypto.PublicKey, hasher crypto.Hash, data, sig []byte) error {
	if sig == nil {
		return errors.New("signature is nil")
	}

	h := hasher.New()
	if _, err := h.Write(data); err != nil {
		return errors.Wrap(err, "write")
	}
	digest := h.Sum(nil)

	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest, sig) {
			return errors.New("verification failed")
		}
	default:
		return fmt.Errorf("unknown public key type: %T", pub)
	}
	return nil
}
