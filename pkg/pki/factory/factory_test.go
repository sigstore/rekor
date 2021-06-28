//
// Copyright 2021 The Sigstore Authors.
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

package factory

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
		name              string
		format            string
		keyFile           string
		sigFile           string
		expectSuccess     bool
		expectValidFormat bool
	}

	testCases := []TestCase{
		{
			name:              "valid pgp",
			format:            "pgp",
			keyFile:           "../pgp/testdata/valid_armored_public.pgp",
			sigFile:           "../pgp/testdata/hello_world.txt.asc.sig",
			expectSuccess:     true,
			expectValidFormat: true,
		},
		{
			name:              "valid minisign",
			format:            "minisign",
			keyFile:           "../minisign/testdata/minisign.pub",
			sigFile:           "../minisign/testdata/hello_world.txt.minisig",
			expectSuccess:     true,
			expectValidFormat: true,
		},
		{
			name:              "valid x509",
			format:            "x509",
			keyFile:           "../x509/testdata/ec.pub",
			sigFile:           "../x509/testdata/hello_world.txt.sig",
			expectSuccess:     true,
			expectValidFormat: true,
		},
		{
			name:              "valid ssh",
			format:            "ssh",
			keyFile:           "../ssh/testdata/id_rsa.pub",
			sigFile:           "../ssh/testdata/hello_world.txt.sig",
			expectSuccess:     true,
			expectValidFormat: true,
		},
		{
			name:              "invalid ssh signature",
			format:            "ssh",
			keyFile:           "../ssh/testdata/id_rsa.pub",
			sigFile:           "../ssh/testdata/hello_world.txt",
			expectSuccess:     false,
			expectValidFormat: true,
		},
		{
			name:              "invalid ssh key",
			format:            "ssh",
			keyFile:           "../ssh/testdata/hello_world.txt",
			sigFile:           "../ssh/testdata/hello_world.txt.sig",
			expectSuccess:     false,
			expectValidFormat: true,
		},
		{
			format:            "bogus",
			expectSuccess:     false,
			expectValidFormat: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			factory, err := NewArtifactFactory(PKIFormat(tc.format))
			if tc.expectValidFormat != (err == nil) {
				t.Fatalf("unexpected error initializing factory for %v", tc.format)
			}
			if factory != nil {
				keyFile, _ := os.Open(tc.keyFile)
				_, newKeyErr := factory.NewPublicKey(keyFile)

				sigFile, _ := os.Open(tc.sigFile)
				_, newSigErr := factory.NewSignature(sigFile)

				if tc.expectSuccess {
					if newKeyErr != nil || newSigErr != nil {
						t.Errorf("unexpected error generating public key %v or signature %v", newKeyErr, newSigErr)
					}
				} else { // expect a failure{
					if newKeyErr == nil && newSigErr == nil {
						t.Error("expected error generating public key and signature. got none")
					}
				}
			}
		})
	}
}
