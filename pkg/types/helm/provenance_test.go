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
	"bytes"
	"os"
	"testing"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/pki/pgp"
)

func TestProvenance(t *testing.T) {
	inputProvenance, err := os.Open("tests/test-0.1.0.tgz.prov")
	if err != nil {
		t.Fatalf("could not open provenance file %v", err)
	}

	provenance := Provenance{}
	err = provenance.Unmarshal(inputProvenance)

	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	algorithm, checksum, err := provenance.GetChartAlgorithmHash()

	if err != nil {
		t.Fatalf("Error retrieving chart hash: %v", err)
	}

	if models.HelmV001SchemaChartHashAlgorithmSha256 != algorithm {
		t.Fatalf("Unexpected checksum algorithm. Expected %s, found %s", models.HelmV001SchemaChartHashAlgorithmSha256, algorithm)
	}

	if len(checksum) == 0 {
		t.Fatal("Empty checksum")
	}

	publickeyFile, err := os.Open("tests/test_helm_armor.pub")
	if err != nil {
		t.Fatalf("could not open public key %v", err)
	}

	publicKey, err := pgp.NewPublicKey(publickeyFile)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}

	sig, err := pgp.NewSignature(provenance.Block.ArmoredSignature.Body)
	if err != nil {
		t.Fatalf("Failed to create signature %v", err)
	}

	err = sig.Verify(bytes.NewBuffer(provenance.Block.Bytes), publicKey)

	if err != nil {
		t.Fatalf("Failed to verify signature %v", err)
	}

}

func TestGetChartAlgorithmHashRejectsMultipleCharts(t *testing.T) {
	provenance := Provenance{
		SumCollection: &SumCollection{
			Files: map[string]string{
				"test-0.1.0.tgz":  "sha256:6dec7ea21e655d5796c1e214cfb75b73428b2abfa2e66c8f7bc64ff4a7b3b29f",
				"other-0.1.0.tgz": "not-a-hash-algorithm:../../etc/passwd",
			},
		},
	}

	if algorithm, checksum, err := provenance.GetChartAlgorithmHash(); err == nil {
		t.Fatalf("expected error for provenance with multiple charts, got %s:%s", algorithm, checksum)
	}
}
