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
// +build e2e

package rekord

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	sigx509 "github.com/sigstore/rekor/pkg/pki/x509"
	"github.com/sigstore/rekor/pkg/util"
)

func TestUploadVerifyHashedRekord(t *testing.T) {
	// Create a random artifact and sign it.
	artifactPath := filepath.Join(t.TempDir(), "artifact")
	sigPath := filepath.Join(t.TempDir(), "signature.asc")

	sigx509.CreatedX509SignedArtifact(t, artifactPath, sigPath)

	dataBytes, _ := os.ReadFile(artifactPath)
	h := sha256.Sum256(dataBytes)
	dataSHA := hex.EncodeToString(h[:])

	// Write the public key to a file
	pubPath := filepath.Join(t.TempDir(), "pubKey.asc")

	if err := os.WriteFile(pubPath, []byte(sigx509.RSACert), 0644); err != nil {
		t.Fatal(err)
	}

	// Verify should fail initially
	util.RunCliErr(t, "verify", "--type=hashedrekord", "--pki-format=x509", "--artifact-hash", dataSHA, "--signature", sigPath, "--public-key", pubPath)

	// It should upload successfully.
	out := util.RunCli(t, "upload", "--type=hashedrekord", "--pki-format=x509", "--artifact-hash", dataSHA, "--signature", sigPath, "--public-key", pubPath)
	util.OutputContains(t, out, "Created entry at")

	// Now we should be able to verify it.
	out = util.RunCli(t, "verify", "--type=hashedrekord", "--pki-format=x509", "--artifact-hash", dataSHA, "--signature", sigPath, "--public-key", pubPath)
	util.OutputContains(t, out, "Inclusion Proof:")
	util.OutputContains(t, out, "Checkpoint:")
}
