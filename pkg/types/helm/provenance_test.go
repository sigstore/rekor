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

package helm

import (
	"os"
	"testing"

	"github.com/sigstore/rekor/pkg/pki/pgp"
)

func TestProvenance(t *testing.T) {
	inputProvenance, err := os.Open("../../../tests/test-0.1.0.tgz.prov")
	if err != nil {
		t.Fatalf("could not open provenance file %v", err)
	}

	provenance := Provedance{}
	err = provenance.Unmarshal(inputProvenance)

	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	checksum, err := provenance.GetChartHash()

	if err != nil {
		t.Fatalf("Error retrieving chart hash: %v", err)
	}

	if len(checksum) == 0 {
		t.Fatal("Empty checksum")
	}

	publickeyFile, err := os.Open("../../../tests/test_helm_armor.pub")
	if err != nil {
		t.Fatalf("could not open public key %v", err)
	}

	publicKey, err := pgp.NewPublicKey(publickeyFile)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}

	keyring, err := publicKey.KeyRing()

	if err != nil {
		t.Fatalf("error obtaining keyring: %v", err)
	}

	err = provenance.VerifySignature(keyring, provenance.ArmoredSignature.Body)

	if err != nil {
		t.Fatalf("Failed to verify signature %v", err)
	}

}
