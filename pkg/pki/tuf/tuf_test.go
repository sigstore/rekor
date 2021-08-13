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

package tuf

import (
	"bytes"
	"io"
	"os"
	"testing"
)

func TestReadPublicKey(t *testing.T) {
	// Tests reading a valid public key (root.json)
	type test struct {
		caseDesc   string
		inputFile  string
		errorFound bool
	}

	tests := []test{
		{caseDesc: "Unsigned root manifest", inputFile: "testdata/unsigned_root.json", errorFound: true},
		{caseDesc: "Invalid TUF root.json (invalid type)", inputFile: "testdata/timestamp.json", errorFound: true},
		{caseDesc: "Valid TUF root.json", inputFile: "testdata/1.root.json", errorFound: false},
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
	// Tests reading a valid signature (manifest)
	type test struct {
		caseDesc   string
		inputFile  string
		errorFound bool
	}

	tests := []test{
		{caseDesc: "Not a valid TUF manifest", inputFile: "testdata/bogus.json", errorFound: true},
		{caseDesc: "Valid root.json manifest", inputFile: "testdata/timestamp.json", errorFound: false},
		{caseDesc: "Valid timestamp.json manifest", inputFile: "testdata/1.root.json", errorFound: false},
		{caseDesc: "Valid unsigned root.json manifest", inputFile: "testdata/unsigned_root.json", errorFound: false},
	}

	for _, tc := range tests {
		file, err := os.Open(tc.inputFile)
		if err != nil {
			t.Errorf("%v: cannot open %v", tc.caseDesc, tc.inputFile)
		}
		if got, err := NewSignature(file); ((got != nil) == tc.errorFound) || ((err != nil) != tc.errorFound) {
			t.Errorf("%v: unexpected result testing %v: %v", tc.caseDesc, tc.inputFile, got)
		}
	}

}

func TestCanonicalValue(t *testing.T) {
	// Tests equivalence even with different JSON encodings
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
		{caseDesc: "root", input: "testdata/1.root.json", output: "testdata/reformat.1.root.json", match: true},
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
		sigFile  string
		keyFile  string
		verified bool
	}

	tests := []test{
		{caseDesc: "Valid root.json, valid signed timestamp.json", keyFile: "testdata/1.root.json", sigFile: "testdata/timestamp.json", verified: true},
		{caseDesc: "Valid root.json, valid signed root.json", keyFile: "testdata/1.root.json", sigFile: "testdata/1.root.json", verified: true},
		{caseDesc: "Valid root.json, mismatched timestamp.json", keyFile: "testdata/other_root.json", sigFile: "testdata/timestamp.json", verified: false},
		{caseDesc: "Valid root.json, unsigned root.json", keyFile: "testdata/1.root.json", sigFile: "testdata/unsigned_root.json", verified: false},
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

		if err := s.Verify(nil, k); (err == nil) != tc.verified {
			t.Errorf("%v: unexpected result in verifying sigature: %v", tc.caseDesc, err)
		}
	}

	emptyKey := PublicKey{}
	emptySig := Signature{}

	if err := emptySig.Verify(nil, emptyKey); err == nil {
		t.Errorf("expected error when using empty sig to verify")
	}

	sigFile, _ := os.Open("testdata/timestamp.json")
	validSig, _ := NewSignature(sigFile)

	if err := validSig.Verify(bytes.NewReader([]byte("irrelevant")), &emptyKey); err == nil {
		t.Errorf("expected error when using empty key to verify")
	}
}
