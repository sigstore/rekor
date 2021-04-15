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
	"context"
	"crypto"
	"testing"

	"github.com/sigstore/rekor/pkg/signer"
)

func TestVerify(t *testing.T) {
	signer, err := signer.NewMemory()
	if err != nil {
		t.Fatalf("getting signer: %v", signer)
	}

	// sign and verify
	ctx := context.Background()
	msg := []byte("foo")
	signature, _, err := signer.Sign(ctx, msg)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	// get public key
	pubKey, err := signer.PublicKey(ctx)
	if err != nil {
		t.Fatalf("getting public key: %v", err)
	}

	// verify should work with correct signature
	if err := Verify(pubKey, crypto.SHA256, msg, signature); err != nil {
		t.Fatalf("error verifying: %v", err)
	}

	// and fail with an incorrect signature
	if err := Verify(pubKey, crypto.SHA256, msg, []byte("nope")); err == nil {
		t.Fatalf("expected failure with incorrect signature")
	}
}
