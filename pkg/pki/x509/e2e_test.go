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

package x509

import (
	"os"
	"path/filepath"
	"testing"

	e2ex509 "github.com/sigstore/rekor/pkg/pki/x509/e2ex509"
	e2eutil "github.com/sigstore/rekor/pkg/util/e2eutil"
)

func TestX509(t *testing.T) {
	td := t.TempDir()
	artifactPath := filepath.Join(td, "artifact")
	sigPath := filepath.Join(td, "signature")
	certPath := filepath.Join(td, "cert.pem")
	pubKeyPath := filepath.Join(td, "key.pem")

	e2ex509.CreatedX509SignedArtifact(t, artifactPath, sigPath)

	if err := os.WriteFile(certPath, []byte(e2ex509.RSACert), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubKeyPath, []byte(e2ex509.PubKey), 0o644); err != nil {
		t.Fatal(err)
	}

	// If we do it twice, it should already exist
	out := e2eutil.RunCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", certPath, "--pki-format", "x509")
	e2eutil.OutputContains(t, out, "Created entry at")
	out = e2eutil.RunCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", certPath, "--pki-format", "x509")
	e2eutil.OutputContains(t, out, "Entry already exists")

	// Now upload with the public key rather than the cert. They should NOT be deduped.
	out = e2eutil.RunCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", pubKeyPath, "--pki-format", "x509")
	e2eutil.OutputContains(t, out, "Created entry at")

	// Now let's go the other order to be sure. New artifact, key first then cert.
	e2ex509.CreatedX509SignedArtifact(t, artifactPath, sigPath)

	out = e2eutil.RunCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", pubKeyPath, "--pki-format", "x509")
	e2eutil.OutputContains(t, out, "Created entry at")
	out = e2eutil.RunCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", pubKeyPath, "--pki-format", "x509")
	e2eutil.OutputContains(t, out, "Entry already exists")
	// This should NOT already exist
	out = e2eutil.RunCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", certPath, "--pki-format", "x509")
	e2eutil.OutputContains(t, out, "Created entry at")
	uuid := e2eutil.GetUUIDFromUploadOutput(t, out)

	// Search via email
	out = e2eutil.RunCli(t, "search", "--email", "test@rekor.dev")
	e2eutil.OutputContains(t, out, uuid)
}
