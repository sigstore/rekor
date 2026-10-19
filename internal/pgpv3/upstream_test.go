// Copyright 2026 The Sigstore Authors.
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

package pgpv3

import (
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
)

// These digests come from the original pgpkeys-eu files at the commit pinned
// in UPSTREAM.md. Upstream files must stay unchanged, including formatting.
func TestUpstreamFilesUnmodified(t *testing.T) {
	for path, want := range map[string]string{
		"upstream/LICENSE":           "2d36597f7117c38b006835ae7f537487207d8ec407aa9d9980794b2030cbc067",
		"upstream/PATENTS":           "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc",
		"upstream/algorithm/hash.go": "0bab823417da3a9186870fffcaac1e29805127e2ecc7be42b1cfa34514212ea2",
		"upstream/encoding/mpi.go":   "43991e775e01460e239de8287dfc859b81ac975326023855123186aa532cc8a5",
	} {
		t.Run(path, func(t *testing.T) {
			contents, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprintf("%x", sha256.Sum256(contents)); got != want {
				t.Fatalf("upstream file changed: SHA256 = %s, want %s; put adaptations outside upstream/", got, want)
			}
		})
	}
}
