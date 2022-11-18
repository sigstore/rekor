//
// Copyright 2022 The Sigstore Authors.
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

//go:build e2e

package rpm

import (
	"github.com/sigstore/rekor/pkg/util"
	"io/ioutil"
	"path/filepath"
	"testing"
)

var publicKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

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
WR6Fv7ySHTl7cQ13jGmSR1N8hg==
=Fen+
-----END PGP PUBLIC KEY BLOCK-----`

func TestUploadVerifyRpm(t *testing.T) {
	// Create a random rpm and sign it.
	td := t.TempDir()
	rpmPath := filepath.Join(td, "rpm")

	CreateSignedRpm(t, rpmPath)

	// Write the public key to a file
	pubPath := filepath.Join(t.TempDir(), "pubKey.asc")
	if err := ioutil.WriteFile(pubPath, []byte(publicKey), 0644); err != nil {
		t.Fatal(err)
	}

	// Verify should fail initially
	util.RunCliErr(t, "verify", "--type=rpm", "--artifact", rpmPath, "--public-key", pubPath)

	// It should upload successfully.
	out := util.RunCli(t, "upload", "--type=rpm", "--artifact", rpmPath, "--public-key", pubPath)
	util.OutputContains(t, out, "Created entry at")

	// Now we should be able to verify it.
	out = util.RunCli(t, "verify", "--type=rpm", "--artifact", rpmPath, "--public-key", pubPath)
	util.OutputContains(t, out, "Inclusion Proof:")
}
