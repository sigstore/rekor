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

package pgp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
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
		{caseDesc: "Not a valid armored public key file", inputFile: "testdata/hello_world.txt.asc.sig", errorFound: true},
		{caseDesc: "Armored private key (should fail)", inputFile: "testdata/armored_private.pgp", errorFound: true},
		{caseDesc: "Valid armored public key", inputFile: "testdata/valid_armored_public.pgp", errorFound: false},
		{caseDesc: "Valid armored public key with multiple subentries", inputFile: "testdata/valid_armored_complex_public.pgp", errorFound: false},
		{caseDesc: "Not a valid binary public key", inputFile: "testdata/bogus_binary.pgp", errorFound: true},
		{caseDesc: "Binary private key (should fail)", inputFile: "testdata/binary_private.pgp", errorFound: true},
		{caseDesc: "Valid binary public key", inputFile: "testdata/valid_binary_public.pgp", errorFound: false},
		{caseDesc: "Valid binary public key with multiple subentries", inputFile: "testdata/valid_binary_complex_public.pgp", errorFound: false},
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
		{caseDesc: "Not a valid signature file", inputFile: "testdata/bogus_armored.pgp", errorFound: true},
		{caseDesc: "Invalid armored signature", inputFile: "testdata/valid_armored_public.pgp", errorFound: true},
		{caseDesc: "Valid armored signature", inputFile: "testdata/hello_world.txt.asc.sig", errorFound: false},
		{caseDesc: "Valid binary signature", inputFile: "testdata/hello_world.txt.sig", errorFound: false},
		{caseDesc: "Valid armored V3 signature", inputFile: "testdata/hello_world.txt.asc.v3.sig", errorFound: false},
		{caseDesc: "Valid binary V3 signature", inputFile: "testdata/hello_world.txt.v3.sig", errorFound: false},
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

func TestFetchPublicKey(t *testing.T) {
	type test struct {
		caseDesc   string
		inputFile  string
		errorFound bool
	}

	testServer := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path[1:] == "premature_close" {
				return
			}

			file, err := ioutil.ReadFile(r.URL.Path[1:])
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(file)
		}))
	defer testServer.Close()

	tests := []test{
		{caseDesc: "Not a valid URL", inputFile: "%invalid_url%", errorFound: true},
		{caseDesc: "HTTP server prematurely closes transaction", inputFile: "premature_close", errorFound: true},
		{caseDesc: "404 error fetching content", inputFile: "not_a_file", errorFound: true},
		{caseDesc: "Invalid public key", inputFile: "testdata/bogus_armored.pgp", errorFound: true},
		{caseDesc: "Private key (should fail)", inputFile: "testdata/armored_private.pgp", errorFound: true},
		{caseDesc: "Valid armored public key", inputFile: "testdata/valid_armored_public.pgp", errorFound: false},
		{caseDesc: "Valid armored public key with multiple subentries", inputFile: "testdata/valid_armored_complex_public.pgp", errorFound: false},
	}

	for _, tc := range tests {
		if got, err := FetchPublicKey(context.TODO(), testServer.URL+"/"+tc.inputFile); ((got != nil) == tc.errorFound) || ((err != nil) != tc.errorFound) {
			t.Errorf("%v: unexpected result testing %v: %v", tc.caseDesc, tc.inputFile, got)
		}
	}
}

func TestFetchSignature(t *testing.T) {
	type test struct {
		caseDesc   string
		inputFile  string
		errorFound bool
	}

	testServer := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path[1:] == "premature_close" {
				return
			}

			file, err := ioutil.ReadFile(r.URL.Path[1:])
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(file)
		}))
	defer testServer.Close()

	tests := []test{
		{caseDesc: "Not a valid URL", inputFile: "%invalid_url%", errorFound: true},
		{caseDesc: "HTTP server prematurely closes transaction", inputFile: "premature_close", errorFound: true},
		{caseDesc: "404 error fetching content", inputFile: "not_a_file", errorFound: true},
		{caseDesc: "Invalid signature", inputFile: "testdata/bogus_armored.pgp", errorFound: true},
		{caseDesc: "Valid armored signature", inputFile: "testdata/hello_world.txt.asc.sig", errorFound: false},
		{caseDesc: "Valid binary signature", inputFile: "testdata/hello_world.txt.sig", errorFound: false},
	}

	for _, tc := range tests {
		if got, err := FetchSignature(context.TODO(), testServer.URL+"/"+tc.inputFile); ((got != nil) == tc.errorFound) || ((err != nil) != tc.errorFound) {
			t.Errorf("%v: unexpected result testing %v: %v", tc.caseDesc, tc.inputFile, got)
		}
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
			caseDesc:      "Binary signature and canonicalized (armored) signature both verify the same file",
			inputFile:     "testdata/hello_world.txt",
			keyFile:       "testdata/valid_armored_public.pgp",
			sigFile:       "testdata/hello_world.txt.sig",
			expectSuccess: true,
		},
		{
			caseDesc:      "Armored signature and canonicalized (armored) signature both verify the same file",
			inputFile:     "testdata/hello_world.txt",
			keyFile:       "testdata/valid_armored_public.pgp",
			sigFile:       "testdata/hello_world.txt.asc.sig",
			expectSuccess: true,
		},
		{
			caseDesc:      "Binary V3 signature and canonicalized (armored) signature both verify the same file",
			inputFile:     "testdata/hello_world.txt",
			keyFile:       "testdata/valid_armored_public.pgp",
			sigFile:       "testdata/hello_world.txt.v3.sig",
			expectSuccess: true,
		},
		{
			caseDesc:      "Armored V3 signature and canonicalized (armored) signature both verify the same file",
			inputFile:     "testdata/hello_world.txt",
			keyFile:       "testdata/valid_armored_public.pgp",
			sigFile:       "testdata/hello_world.txt.asc.v3.sig",
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
		}

		_, _ = inputFile.Seek(0, io.SeekStart)

		if err := canonicalSig.Verify(inputFile, key); (err == nil) != tc.expectSuccess {
			t.Errorf("%v: canonical signature was unable to be verified: %v", tc.caseDesc, err)
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
		{caseDesc: "Binary and Armored versions of same key", input: "testdata/valid_binary_public.pgp", output: "testdata/valid_armored_public.pgp", match: true},
		{caseDesc: "Complex binary and armored versions of same key", input: "testdata/valid_binary_complex_public.pgp", output: "testdata/valid_armored_complex_public.pgp", match: true},
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
		{caseDesc: "Valid Armored Signature, Armored Key", dataFile: "testdata/hello_world.txt", sigFile: "testdata/hello_world.txt.asc.sig", keyFile: "testdata/valid_armored_public.pgp", verified: true},
		{caseDesc: "Valid Armored Signature, Binary Key", dataFile: "testdata/hello_world.txt", sigFile: "testdata/hello_world.txt.asc.sig", keyFile: "testdata/valid_binary_public.pgp", verified: true},
		{caseDesc: "Valid Binary Signature, Armored Key", dataFile: "testdata/hello_world.txt", sigFile: "testdata/hello_world.txt.sig", keyFile: "testdata/valid_armored_public.pgp", verified: true},
		{caseDesc: "Valid Binary Signature, Binary Key", dataFile: "testdata/hello_world.txt", sigFile: "testdata/hello_world.txt.sig", keyFile: "testdata/valid_binary_public.pgp", verified: true},
		{caseDesc: "Valid V3 Armored Signature, Armored Key", dataFile: "testdata/hello_world.txt", sigFile: "testdata/hello_world.txt.asc.v3.sig", keyFile: "testdata/valid_armored_public.pgp", verified: true},
		{caseDesc: "Valid V3 Armored Signature, Binary Key", dataFile: "testdata/hello_world.txt", sigFile: "testdata/hello_world.txt.asc.v3.sig", keyFile: "testdata/valid_binary_public.pgp", verified: true},
		{caseDesc: "Valid V3 Binary Signature, Armored Key", dataFile: "testdata/hello_world.txt", sigFile: "testdata/hello_world.txt.v3.sig", keyFile: "testdata/valid_armored_public.pgp", verified: true},
		{caseDesc: "Valid V3 Binary Signature, Binary Key", dataFile: "testdata/hello_world.txt", sigFile: "testdata/hello_world.txt.v3.sig", keyFile: "testdata/valid_binary_public.pgp", verified: true},
		{caseDesc: "Valid Signature, Incorrect Key", dataFile: "testdata/hello_world.txt", sigFile: "testdata/hello_world.txt.sig", keyFile: "testdata/valid_binary_complex_public.pgp", verified: false},
		{caseDesc: "Data does not match Signature", dataFile: "testdata/armored_private.pgp", sigFile: "testdata/hello_world.txt.sig", keyFile: "testdata/valid_binary_complex_public.pgp", verified: false},
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

	sigFile, _ := os.Open("testdata/hello_world.txt.sig")
	validSig, _ := NewSignature(sigFile)

	if err := validSig.Verify(bytes.NewReader([]byte("irrelevant")), &emptyKey); err == nil {
		t.Errorf("expected error when using empty key to verify")
	}

	if err := validSig.Verify(bytes.NewReader([]byte("irrelevant")), sigFile); err == nil {
		t.Errorf("expected error when using non key to verify")
	}
}
