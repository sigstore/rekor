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

package alpine

import (
	"os"
	"testing"

	"github.com/sigstore/rekor/pkg/pki/x509"
)

func TestAlpinePackage(t *testing.T) {
	inputArchive, err := os.Open("tests/test_alpine.apk")
	if err != nil {
		t.Fatalf("could not open archive %v", err)
	}

	p := Package{}
	err = p.Unmarshal(inputArchive)
	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	pubKey, err := os.Open("tests/test_alpine.pub")
	if err != nil {
		t.Fatalf("could not open archive %v", err)
	}

	pub, err := x509.NewPublicKey(pubKey)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}

	if err = p.VerifySignature(pub.CryptoPubKey()); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}
