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

package rfc3161

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"testing"

	e2eutil "github.com/sigstore/rekor/pkg/util/e2eutil"
)

func TestTimestampArtifact(t *testing.T) {
	var out string
	out = e2eutil.RunCli(t, "upload", "--type", "rfc3161", "--artifact", "tests/test.tsr")
	e2eutil.OutputContains(t, out, "Created entry at")
	uuid := e2eutil.GetUUIDFromUploadOutput(t, out)

	artifactBytes, err := ioutil.ReadFile("tests/test.tsr")
	if err != nil {
		t.Error(err)
	}
	sha := sha256.Sum256(artifactBytes)

	out = e2eutil.RunCli(t, "upload", "--type", "rfc3161", "--artifact", "tests/test.tsr")
	e2eutil.OutputContains(t, out, "Entry already exists")

	out = e2eutil.RunCli(t, "search", "--artifact", "tests/test.tsr")
	e2eutil.OutputContains(t, out, uuid)

	out = e2eutil.RunCli(t, "search", "--sha", fmt.Sprintf("sha256:%s", hex.EncodeToString(sha[:])))
	e2eutil.OutputContains(t, out, uuid)
}
