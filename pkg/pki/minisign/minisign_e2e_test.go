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

package minisign

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sigstore/rekor/pkg/util"
)

func TestMinisign(t *testing.T) {
	// Create a keypair
	keyPath := filepath.Join(t.TempDir(), "minisign.key")
	pubPath := filepath.Join(t.TempDir(), "minisign.pub")

	// Set an empty password, we have to hit enter twice to confirm
	util.Run(t, "\n\n", "minisign", "-G", "-s", keyPath, "-p", pubPath)

	// Create a random artifact and sign it.
	artifactPath := filepath.Join(t.TempDir(), "artifact")
	sigPath := filepath.Join(t.TempDir(), "signature.asc")
	util.CreateArtifact(t, artifactPath)

	// Send in one empty password over stdin
	out := util.Run(t, "\n", "minisign", "-S", "-s", keyPath, "-m", artifactPath, "-x", sigPath)
	t.Log(out)

	// Now upload to the log!
	out = util.RunCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", pubPath, "--pki-format", "minisign")
	util.OutputContains(t, out, "Created entry at")

	uuidA := util.GetUUIDFromUploadOutput(t, out)

	out = util.RunCli(t, "verify", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", pubPath, "--pki-format", "minisign")
	util.OutputContains(t, out, "Inclusion Proof")

	out = util.RunCli(t, "search", "--public-key", pubPath, "--pki-format", "minisign")
	util.OutputContains(t, out, uuidA)

	// crease a second artifact and sign it
	artifactPath_B := filepath.Join(t.TempDir(), "artifact2")
	util.CreateArtifact(t, artifactPath_B)
	out = util.Run(t, "\n", "minisign", "-S", "-s", keyPath, "-m", artifactPath_B, "-x", sigPath)
	// Now upload to the log!
	out = util.RunCli(t, "upload", "--artifact", artifactPath_B, "--signature", sigPath,
		"--public-key", pubPath, "--pki-format", "minisign")
	util.OutputContains(t, out, "Created entry at")
	uuidB := util.GetUUIDFromUploadOutput(t, out)

	tests := []struct {
		name               string
		expectedUuidACount int
		expectedUuidBCount int
		artifact           string
		operator           string
	}{
		{
			name:               "artifact A AND signature should return artifact A",
			expectedUuidACount: 1,
			expectedUuidBCount: 0,
			artifact:           artifactPath,
			operator:           "and",
		},
		{
			name:               "artifact A OR signature should return artifact A and B",
			expectedUuidACount: 1,
			expectedUuidBCount: 1,
			artifact:           artifactPath,
			operator:           "or",
		},
		{
			name:               "artifact B AND signature should return artifact B",
			expectedUuidACount: 0,
			expectedUuidBCount: 1,
			artifact:           artifactPath_B,
			operator:           "and",
		},
		{
			name:               "artifact B OR signature should return artifact A and B",
			expectedUuidACount: 1,
			expectedUuidBCount: 1,
			artifact:           artifactPath_B,
			operator:           "or",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out = util.RunCli(t, "search", "--public-key", pubPath, "--pki-format", "minisign",
				"--operator", test.operator, "--artifact", test.artifact)

			expected := map[string]int{uuidA: test.expectedUuidACount, uuidB: test.expectedUuidBCount}
			actual := map[string]int{
				uuidA: strings.Count(out, uuidA),
				uuidB: strings.Count(out, uuidB),
			}
			if !reflect.DeepEqual(expected, actual) {
				t.Errorf("expected to find %v, found %v", expected, actual)
			}
		})
	}
}
