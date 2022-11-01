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

package jar

import (
	"github.com/sigstore/rekor/pkg/util"
	"path/filepath"
	"testing"
)

func TestJAR(t *testing.T) {
	td := t.TempDir()
	artifactPath := filepath.Join(td, "artifact.jar")

	CreateSignedJar(t, artifactPath)

	// If we do it twice, it should already exist
	out := util.RunCli(t, "upload", "--artifact", artifactPath, "--type", "jar")
	util.OutputContains(t, out, "Created entry at")
	out = util.RunCli(t, "upload", "--artifact", artifactPath, "--type", "jar")
	util.OutputContains(t, out, "Entry already exists")
}
