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

package tuf

import (
	"github.com/sigstore/rekor/pkg/util"
	"path/filepath"
	"testing"
)

func TestTufVerifyUpload(t *testing.T) {
	artifactPath := filepath.Join(t.TempDir(), "timestamp.json")
	rootPath := filepath.Join(t.TempDir(), "root.json")

	createTufSignedArtifact(t, artifactPath, rootPath)

	// Now upload to rekor!
	out := util.RunCli(t, "upload", "--artifact", artifactPath, "--public-key", rootPath, "--type", "tuf")
	util.OutputContains(t, out, "Created entry at")

	uuid := util.GetUUIDFromUploadOutput(t, out)

	out = util.RunCli(t, "verify", "--artifact", artifactPath, "--public-key", rootPath, "--type", "tuf")
	util.OutputContains(t, out, "Inclusion Proof")

	out = util.RunCli(t, "search", "--public-key", rootPath, "--pki-format", "tuf")
	util.OutputContains(t, out, uuid)
}
