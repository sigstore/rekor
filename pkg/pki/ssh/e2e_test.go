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

package ssh

import (
	"github.com/sigstore/rekor/pkg/util"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"
)

func TestSSH(t *testing.T) {
	td := t.TempDir()
	// Create a keypair
	keyPath := filepath.Join(td, "id_rsa")
	pubPath := filepath.Join(td, "id_rsa.pub")

	if err := ioutil.WriteFile(pubPath, []byte(publicKey), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(keyPath, []byte(privateKey), 0600); err != nil {
		t.Fatal(err)
	}

	// Create a random artifact and sign it.
	artifactPath := filepath.Join(td, "artifact")
	sigPath := filepath.Join(td, "signature.sig")
	artifact := util.CreateArtifact(t, artifactPath)

	sig := SSHSign(t, strings.NewReader(artifact))
	if err := ioutil.WriteFile(sigPath, []byte(sig), 0600); err != nil {
		t.Fatal(err)
	}

	// Now upload to the log!
	out := util.RunCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", pubPath, "--pki-format", "ssh")
	util.OutputContains(t, out, "Created entry at")

	uuid := util.GetUUIDFromUploadOutput(t, out)

	out = util.RunCli(t, "verify", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", pubPath, "--pki-format", "ssh")
	util.OutputContains(t, out, "Inclusion Proof")

	out = util.RunCli(t, "search", "--public-key", pubPath, "--pki-format", "ssh")
	util.OutputContains(t, out, uuid)
}
