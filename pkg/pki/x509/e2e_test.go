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

package x509

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/rekor/pkg/util"
)

func TestX509(t *testing.T) {
	td := t.TempDir()
	artifactPath := filepath.Join(td, "artifact")
	sigPath := filepath.Join(td, "signature")
	certPath := filepath.Join(td, "cert.pem")
	pubKeyPath := filepath.Join(td, "key.pem")

	CreatedX509SignedArtifact(t, artifactPath, sigPath)

	if err := os.WriteFile(certPath, []byte(RSACert), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubKeyPath, []byte(PubKey), 0o644); err != nil {
		t.Fatal(err)
	}

	// If we do it twice, it should already exist
	out := util.RunCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", certPath, "--pki-format", "x509")
	util.OutputContains(t, out, "Created entry at")
	out = util.RunCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", certPath, "--pki-format", "x509")
	util.OutputContains(t, out, "Entry already exists")

	// Now upload with the public key rather than the cert. They should NOT be deduped.
	out = util.RunCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", pubKeyPath, "--pki-format", "x509")
	util.OutputContains(t, out, "Created entry at")

	// Now let's go the other order to be sure. New artifact, key first then cert.
	CreatedX509SignedArtifact(t, artifactPath, sigPath)

	out = util.RunCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", pubKeyPath, "--pki-format", "x509")
	util.OutputContains(t, out, "Created entry at")
	out = util.RunCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", pubKeyPath, "--pki-format", "x509")
	util.OutputContains(t, out, "Entry already exists")
	// This should NOT already exist
	out = util.RunCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", certPath, "--pki-format", "x509")
	util.OutputContains(t, out, "Created entry at")
	uuid := util.GetUUIDFromUploadOutput(t, out)

	// Search via email
	out = util.RunCli(t, "search", "--email", "test@rekor.dev")
	util.OutputContains(t, out, uuid)
}
