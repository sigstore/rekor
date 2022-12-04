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

package main

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/sigstore/rekor/pkg/util"
)

func TestDuplicates(t *testing.T) {
	artifactPath := filepath.Join(t.TempDir(), "artifact")
	sigPath := filepath.Join(t.TempDir(), "signature.asc")

	util.CreatedPGPSignedArtifact(t, artifactPath, sigPath)

	// Write the public key to a file
	pubPath := filepath.Join(t.TempDir(), "pubKey.asc")
	if err := ioutil.WriteFile(pubPath, []byte(util.PubKey), 0644); err != nil {
		t.Fatal(err)
	}

	// Now upload to rekor!
	out := util.RunCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath, "--public-key", pubPath)
	util.OutputContains(t, out, "Created entry at")

	// Now upload the same one again, we should get a dupe entry.
	out = util.RunCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath, "--public-key", pubPath)
	util.OutputContains(t, out, "Entry already exists")

	// Now do a new one, we should get a new entry
	util.CreatedPGPSignedArtifact(t, artifactPath, sigPath)
	out = util.RunCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath, "--public-key", pubPath)
	util.OutputContains(t, out, "Created entry at")
}
