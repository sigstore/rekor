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

package minisign

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestReadPublicKey(t *testing.T) {
	type test struct {
		caseDesc   string
		inputFile  string
		errorFound bool
	}

	tests := []test{
		{caseDesc: "Not a valid public key file", inputFile: "testdata/hello_world.txt.minisig", errorFound: true},
		{caseDesc: "Valid public key (minisign)", inputFile: "testdata/minisign.pub", errorFound: false},
		{caseDesc: "Valid public key (signify)", inputFile: "testdata/signify.pub", errorFound: false},
	}

	for _, tc := range tests {
		file, err := os.Open(tc.inputFile)
		if err != nil {
			t.Errorf("%v: cannot open %v", tc.caseDesc, tc.inputFile)
		}

		if got, err := NewPublicKey(file); ((got != nil) == tc.errorFound) || ((err != nil) != tc.errorFound) {
			t.Errorf("%v: unexpected result testing %v: %v", tc.caseDesc, tc.inputFile, err)
		}
	}
}

func TestReadSignature(t *testing.T) {
	type test struct {
		caseDesc   string
		inputFile  string
		errorFound bool
	}

	tests := []test{
		{caseDesc: "Not a valid signature file", inputFile: "testdata/minisign.pub", errorFound: true},
		{caseDesc: "Valid minisign signature", inputFile: "testdata/hello_world.txt.minisig", errorFound: false},
		{caseDesc: "Valid signify signature", inputFile: "testdata/hello_world.txt.signify", errorFound: false},
	}

	for _, tc := range tests {
		file, err := os.Open(tc.inputFile)
		if err != nil {
			t.Errorf("%v: cannot open %v", tc.caseDesc, tc.inputFile)
		}
		if got, err := NewSignature(file); ((got != nil) == tc.errorFound) || ((err != nil) != tc.errorFound) {
			t.Error(err)
			t.Errorf("%v: unexpected result testing %v: %v", tc.caseDesc, tc.inputFile, got)
		}
	}
}

type BadReader struct {
}

func (br BadReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("test error")
}

func TestReadErrorPublicKey(t *testing.T) {
	br := new(BadReader)
	if _, err := NewPublicKey(br); err == nil {
		t.Errorf("KnownBadReader: unexpected success testing a broken reader for public key")
	}
}

func TestReadErrorSignature(t *testing.T) {
	br := new(BadReader)
	if _, err := NewSignature(br); err == nil {
		t.Errorf("KnownBadReader: unexpected success testing a broken reader for signature")
	}
}

func TestCanonicalValueSignature(t *testing.T) {
	type test struct {
		caseDesc      string
		inputFile     string
		keyFile       string
		sigFile       string
		expectSuccess bool
	}

	var s Signature
	if _, err := s.CanonicalValue(); err == nil {
		t.Errorf("CanonicalValue did not error out for uninitialized signature")
	}

	tests := []test{
		{
			caseDesc:      "Minisign key with comment and canonicalized signature both verify the same file",
			inputFile:     "testdata/hello_world.txt",
			keyFile:       "testdata/minisign.pub",
			sigFile:       "testdata/hello_world.txt.minisig",
			expectSuccess: true,
		},
		{
			caseDesc:      "Standalone minisign key and canonicalized signature both verify the same file",
			inputFile:     "testdata/hello_world.txt",
			keyFile:       "testdata/minisign_key_only.pub",
			sigFile:       "testdata/hello_world.txt.minisig",
			expectSuccess: true,
		},
		{
			caseDesc:      "Signify key and canonicalized signature both verify the same file",
			inputFile:     "testdata/hello_world.txt",
			keyFile:       "testdata/signify.pub",
			sigFile:       "testdata/hello_world.txt.signify",
			expectSuccess: true,
		},
	}

	for _, tc := range tests {
		var err error
		inputFile, err := os.Open(tc.inputFile)
		if err != nil {
			t.Errorf("%v: cannot open %v", tc.caseDesc, tc.inputFile)
		}

		sigFile, err := os.Open(tc.sigFile)
		if err != nil {
			t.Errorf("%v: cannot open %v", tc.caseDesc, tc.sigFile)
		}

		keyFile, err := os.Open(tc.keyFile)
		if err != nil {
			t.Errorf("%v: cannot open %v", tc.caseDesc, tc.keyFile)
		}

		key, err := NewPublicKey(keyFile)
		if err != nil {
			t.Errorf("%v: Error reading public key for TestCanonicalValueSignature: %v", tc.caseDesc, err)
		}

		sig, err := NewSignature(sigFile)
		if err != nil {
			t.Errorf("%v: Error reading signature for TestCanonicalValueSignature: %v", tc.caseDesc, err)
		}

		if err := sig.Verify(inputFile, key); err != nil {
			t.Errorf("%v: Error verifying pre-canonicalized signature for TestCanonicalValueSignature: %v", tc.caseDesc, err)
		}

		canonicalSigBytes, err := sig.CanonicalValue()
		if err != nil {
			t.Errorf("%v: Error canonicalizing signature '%v': %v", tc.caseDesc, tc.sigFile, err)
		}

		canonicalSig, err := NewSignature(bytes.NewReader(canonicalSigBytes))
		if err != nil {
			t.Errorf("%v: Error reading canonicalized signature for TestCanonicalValueSignature: %v", tc.caseDesc, err)
		} else {
			_, _ = inputFile.Seek(0, io.SeekStart)

			if err := canonicalSig.Verify(inputFile, key); (err == nil) != tc.expectSuccess {
				t.Errorf("%v: canonical signature was unable to be verified: %v", tc.caseDesc, err)
			}
		}
	}
}

func TestCanonicalValuePublicKey(t *testing.T) {
	type test struct {
		caseDesc string
		input    string
		output   string
		match    bool
	}

	var k PublicKey
	if _, err := k.CanonicalValue(); err == nil {
		t.Errorf("CanonicalValue did not error out for uninitialized key")
	}

	tests := []test{
		{caseDesc: "key", input: "testdata/minisign.pub", output: "testdata/minisign_key_only.pub", match: true},
	}

	for _, tc := range tests {
		var inputFile, outputFile io.Reader
		var err error
		inputFile, err = os.Open(tc.input)
		if err != nil {
			t.Errorf("%v: cannot open %v", tc.caseDesc, tc.input)
		}

		inputKey, err := NewPublicKey(inputFile)
		if err != nil {
			t.Errorf("%v: Error reading input for TestCanonicalValuePublicKey: %v", tc.caseDesc, err)
		}

		cvInput, err := inputKey.CanonicalValue()
		if err != nil {
			t.Errorf("%v: Error canonicalizing public key '%v': %v", tc.caseDesc, tc.input, err)
		}

		outputFile, err = os.Open(tc.output)
		if err != nil {
			t.Errorf("%v: cannot open %v", tc.caseDesc, tc.output)
		}

		outputKey, err := NewPublicKey(outputFile)
		if err != nil {
			t.Errorf("%v: Error reading input for TestCanonicalValuePublicKey: %v", tc.caseDesc, err)
		}

		cvOutput, err := outputKey.CanonicalValue()
		if err != nil {
			t.Errorf("%v: Error canonicalizing public key '%v': %v", tc.caseDesc, tc.input, err)
		}

		if bytes.Equal(cvInput, cvOutput) != tc.match {
			t.Errorf("%v: %v equality of canonical values of %v and %v was expected but not generated", tc.caseDesc, tc.match, tc.input, tc.output)
		}
	}
}

func TestVerifySignature(t *testing.T) {
	type test struct {
		caseDesc string
		dataFile string
		sigFile  string
		keyFile  string
		verified bool
	}

	tests := []test{
		{caseDesc: "Valid Signature (minisign), Valid Key", dataFile: "testdata/hello_world.txt", sigFile: "testdata/hello_world.txt.minisig", keyFile: "testdata/minisign.pub", verified: true},
		{caseDesc: "Valid Signature (signify), Valid Key", dataFile: "testdata/hello_world.txt", sigFile: "testdata/hello_world.txt.signify", keyFile: "testdata/signify.pub", verified: true},
		{caseDesc: "Valid Signature, Incorrect Key", dataFile: "testdata/hello_world.txt", sigFile: "testdata/hello_world.txt.minisig", keyFile: "testdata/signify.pub", verified: false},
		{caseDesc: "Data does not match Signature", dataFile: "testdata/signify.pub", sigFile: "testdata/hello_world.txt.minisig", keyFile: "testdata/minisign.pub", verified: false},
	}

	for _, tc := range tests {
		keyFile, err := os.Open(tc.keyFile)
		if err != nil {
			t.Errorf("%v: error reading keyfile '%v': %v", tc.caseDesc, tc.keyFile, err)
		}
		k, err := NewPublicKey(keyFile)
		if err != nil {
			t.Errorf("%v: error reading keyfile '%v': %v", tc.caseDesc, tc.keyFile, err)
		}

		sigFile, err := os.Open(tc.sigFile)
		if err != nil {
			t.Errorf("%v: error reading sigfile '%v': %v", tc.caseDesc, tc.sigFile, err)
		}
		s, err := NewSignature(sigFile)
		if err != nil {
			t.Errorf("%v: error reading sigfile '%v': %v", tc.caseDesc, tc.sigFile, err)
		}

		dataFile, err := os.Open(tc.dataFile)
		if err != nil {
			t.Errorf("%v: error reading datafile '%v': %v", tc.caseDesc, tc.dataFile, err)
		}

		if err := s.Verify(dataFile, k); (err == nil) != tc.verified {
			t.Errorf("%v: unexpected result in verifying sigature: %v", tc.caseDesc, err)
		}
	}

	emptyKey := PublicKey{}
	emptySig := Signature{}

	if err := emptySig.Verify(bytes.NewReader([]byte("irrelevant")), emptyKey); err == nil {
		t.Errorf("expected error when using empty sig to verify")
	}

	sigFile, _ := os.Open("testdata/hello_world.txt.minisig")
	validSig, _ := NewSignature(sigFile)

	if err := validSig.Verify(bytes.NewReader([]byte("irrelevant")), &emptyKey); err == nil {
		t.Errorf("expected error when using empty key to verify")
	}

	if err := validSig.Verify(bytes.NewReader([]byte("irrelevant")), sigFile); err == nil {
		t.Errorf("expected error when using non key to verify")
	}
}
