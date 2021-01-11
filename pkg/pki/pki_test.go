/*
Copyright © 2020 Bob Callaway <bcallawa@redhat.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package pki

import (
	"os"
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestFactoryNewKey(t *testing.T) {
	type TestCase struct {
		format        string
		keyFile       string
		sigFile       string
		expectSuccess bool
	}

	testCases := []TestCase{
		{
			format:        "pgp",
			keyFile:       "pgp/testdata/valid_armored_public.pgp",
			sigFile:       "pgp/testdata/hello_world.txt.asc.sig",
			expectSuccess: true,
		},
		{
			format:        "minisign",
			keyFile:       "minisign/testdata/minisign.pub",
			sigFile:       "minisign/testdata/hello_world.txt.minisig",
			expectSuccess: true,
		},
		{
			format:        "bogus",
			expectSuccess: false,
		},
	}

	for _, tc := range testCases {
		factory := NewArtifactFactory(tc.format)
		keyFile, _ := os.Open(tc.keyFile)
		if _, err := factory.NewPublicKey(keyFile); (err == nil) != tc.expectSuccess {
			t.Errorf("unexpected error generating public key for '%v': %v", tc.format, err)
		}
		sigFile, _ := os.Open(tc.sigFile)
		if _, err := factory.NewSignature(sigFile); (err == nil) != tc.expectSuccess {
			t.Errorf("unexpected error generating signature for '%v': %v", tc.format, err)
		}
	}
}
