//
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

//go:build e2e

package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/rekor/pkg/pki/x509/testutils"
	e2eutil "github.com/sigstore/rekor/pkg/util/e2eutil"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func TestSearchBySANSubject(t *testing.T) {
	const sanURI = "https://github.com/sofico-codebase/.github/.github/workflows/fabric-build.yaml@refs/heads/main"

	td := t.TempDir()
	artifactPath := filepath.Join(td, "artifact")
	sigPath := filepath.Join(td, "signature")
	certPath := filepath.Join(td, "chain.pem")

	rootCert, rootKey, err := testutils.GenerateRootCa()
	if err != nil {
		t.Fatalf("root ca: %v", err)
	}
	subCert, subKey, err := testutils.GenerateSubordinateCa(rootCert, rootKey)
	if err != nil {
		t.Fatalf("sub ca: %v", err)
	}
	u, err := url.Parse(sanURI)
	if err != nil {
		t.Fatalf("parse uri: %v", err)
	}
	leafCert, leafKey, err := testutils.GenerateLeafCertWithSubjectAlternateNames(
		nil, nil, []net.IP{}, []*url.URL{u},
		"https://token.actions.githubusercontent.com",
		subCert, subKey,
	)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}

	pemChain, err := cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{leafCert, subCert, rootCert})
	if err != nil {
		t.Fatalf("marshal chain: %v", err)
	}
	if err := os.WriteFile(certPath, pemChain, 0o644); err != nil {
		t.Fatal(err)
	}

	artifact := e2eutil.CreateArtifact(t, artifactPath)
	digest := sha256.Sum256([]byte(artifact))
	sig, err := ecdsa.SignASN1(rand.Reader, leafKey, digest[:])
	if err != nil {
		t.Fatalf("sign artifact: %v", err)
	}
	if err := os.WriteFile(sigPath, sig, 0o644); err != nil {
		t.Fatal(err)
	}

	out := e2eutil.RunCli(t, "upload",
		"--type", "hashedrekord:0.0.1",
		"--artifact-hash", "sha256:"+hex.EncodeToString(digest[:]),
		"--signature", sigPath,
		"--public-key", certPath,
		"--pki-format", "x509",
	)
	e2eutil.OutputContains(t, out, "Created entry at")
	uuid := e2eutil.GetUUIDFromUploadOutput(t, out)

	out = e2eutil.RunCli(t, "search", "--subject", sanURI)
	e2eutil.OutputContains(t, out, uuid)

	mangled := strings.ToUpper(sanURI)
	if mangled == sanURI {
		t.Fatalf("test setup: mangled string equals original")
	}
	out = e2eutil.RunCli(t, "search", "--subject", mangled)
	e2eutil.OutputContains(t, out, uuid)
}
