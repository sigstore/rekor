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

package alpine

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	sigx509 "github.com/sigstore/rekor/pkg/pki/x509"
	"github.com/sigstore/rekor/pkg/util"
)

func TestAPK(t *testing.T) {
	td := t.TempDir()
	artifactPath := filepath.Join(td, "artifact.apk")

	CreateSignedApk(t, artifactPath)

	pubPath := filepath.Join(t.TempDir(), "pubKey.asc")
	if err := ioutil.WriteFile(pubPath, []byte(sigx509.PubKey), 0644); err != nil {
		t.Fatal(err)
	}

	// If we do it twice, it should already exist
	out := util.RunCli(t, "upload", "--artifact", artifactPath, "--type", "alpine", "--public-key", pubPath)
	util.OutputContains(t, out, "Created entry at")
	out = util.RunCli(t, "upload", "--artifact", artifactPath, "--type", "alpine", "--public-key", pubPath)
	util.OutputContains(t, out, "Entry already exists")
	// pass invalid public key, ensure we see an error with helpful message
	out = util.RunCliErr(t, "upload", "--artifact", artifactPath, "--type", "alpine", "--public-key", artifactPath)
	util.OutputContains(t, out, "invalid public key")
}
