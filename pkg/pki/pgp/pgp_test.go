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

package pgp

import (
	"bytes"
	"context"
	"crypto"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
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
		{caseDesc: "Valid armored public key for V3 signature", inputFile: "testdata/repomd_armored_public.pgp", errorFound: false},
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
		{caseDesc: "Valid armored V4 signature", inputFile: "testdata/hello_world.txt.asc.v4.sig", errorFound: false},
		{caseDesc: "Valid binary V4 signature", inputFile: "testdata/hello_world.txt.v4.sig", errorFound: false},
		{caseDesc: "Valid armored V3 signature", inputFile: "testdata/repomd.xml.asc.sig", errorFound: false},
		{caseDesc: "Valid binary V3 signature", inputFile: "testdata/repomd.xml.sig", errorFound: false},
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

func (br BadReader) Read(_ []byte) (n int, err error) {
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

			file, err := os.ReadFile(r.URL.Path[1:])
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

			file, err := os.ReadFile(r.URL.Path[1:])
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
			caseDesc:      "Binary V4 signature and canonicalized (armored) signature both verify the same file",
			inputFile:     "testdata/hello_world.txt",
			keyFile:       "testdata/valid_armored_public.pgp",
			sigFile:       "testdata/hello_world.txt.v4.sig",
			expectSuccess: true,
		},
		{
			caseDesc:      "Armored V4 signature and canonicalized (armored) signature both verify the same file",
			inputFile:     "testdata/hello_world.txt",
			keyFile:       "testdata/valid_armored_public.pgp",
			sigFile:       "testdata/hello_world.txt.asc.v4.sig",
			expectSuccess: true,
		},
		{
			caseDesc:      "Binary V3 signature and canonicalized (armored) signature both verify the same file",
			inputFile:     "testdata/repomd.xml",
			keyFile:       "testdata/repomd_armored_public.pgp",
			sigFile:       "testdata/repomd.xml.sig",
			expectSuccess: true,
		},
		{
			caseDesc:      "Armored V3 signature and canonicalized (armored) signature both verify the same file",
			inputFile:     "testdata/repomd.xml",
			keyFile:       "testdata/repomd_armored_public.pgp",
			sigFile:       "testdata/repomd.xml.asc.sig",
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

func TestEmailAddresses(t *testing.T) {
	type test struct {
		caseDesc  string
		inputFile string
		subjects  []string
		// number of keys in key ring
		// verified with gpg, ignoring DSA/ElGamal keys
		keys int
	}

	var k PublicKey
	if len(k.Subjects()) != 0 {
		t.Errorf("Subjects for uninitialized key should give empty slice")
	}
	tests := []test{
		{caseDesc: "Valid armored public key", inputFile: "testdata/valid_armored_public.pgp", subjects: []string{"not@real.com"}, keys: 2},
		{caseDesc: "Valid armored public key with multiple subentries", inputFile: "testdata/valid_armored_complex_public.pgp", subjects: []string{"linux-packages-keymaster@google.com", "linux-packages-keymaster@google.com"}, keys: 4},
		{caseDesc: "Valid binary public key", inputFile: "testdata/valid_binary_public.pgp", subjects: []string{"not@real.com"}, keys: 2},
		{caseDesc: "Valid binary public key with multiple subentries", inputFile: "testdata/valid_binary_complex_public.pgp", subjects: []string{"linux-packages-keymaster@google.com", "linux-packages-keymaster@google.com"}, keys: 4},
	}

	for _, tc := range tests {
		var input io.Reader
		var err error
		input, err = os.Open(tc.inputFile)
		if err != nil {
			t.Errorf("%v: cannot open %v", tc.caseDesc, tc.inputFile)
		}

		inputKey, err := NewPublicKey(input)
		if err != nil {
			t.Errorf("%v: Error reading input for TestEmailAddresses: %v", tc.caseDesc, err)
		}

		subjects := inputKey.Subjects()

		if len(subjects) == len(tc.subjects) {
			if len(subjects) > 0 {
				sort.Strings(subjects)
				sort.Strings(tc.subjects)
				if !reflect.DeepEqual(subjects, tc.subjects) {
					t.Errorf("%v: Error getting subjects from keys, got %v, expected %v", tc.caseDesc, subjects, tc.subjects)
				}
			}
		} else {
			t.Errorf("%v: Error getting subjects from keys length, got %v, expected %v", tc.caseDesc, len(subjects), len(tc.subjects))
		}

		ids, err := inputKey.Identities()
		if err != nil {
			t.Fatalf("%v: unexpected error getting identities: %v", tc.caseDesc, err)
		}
		if len(ids) != tc.keys {
			t.Fatalf("%v: expected %d keys, got %d", tc.caseDesc, tc.keys, len(ids))
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
		{caseDesc: "Valid V4 Armored Signature, Armored Key", dataFile: "testdata/hello_world.txt", sigFile: "testdata/hello_world.txt.asc.v4.sig", keyFile: "testdata/valid_armored_public.pgp", verified: true},
		{caseDesc: "Valid V4 Armored Signature, Binary Key", dataFile: "testdata/hello_world.txt", sigFile: "testdata/hello_world.txt.asc.v4.sig", keyFile: "testdata/valid_binary_public.pgp", verified: true},
		{caseDesc: "Valid V4 Binary Signature, Armored Key", dataFile: "testdata/hello_world.txt", sigFile: "testdata/hello_world.txt.v4.sig", keyFile: "testdata/valid_armored_public.pgp", verified: true},
		{caseDesc: "Valid V4 Binary Signature, Binary Key", dataFile: "testdata/hello_world.txt", sigFile: "testdata/hello_world.txt.v4.sig", keyFile: "testdata/valid_binary_public.pgp", verified: true},
		{caseDesc: "Valid V3 Armored Signature, Armored Key", dataFile: "testdata/repomd.xml", sigFile: "testdata/repomd.xml.asc.sig", keyFile: "testdata/repomd_armored_public.pgp", verified: true},
		{caseDesc: "Valid V3 Binary Signature, Armored Key", dataFile: "testdata/repomd.xml", sigFile: "testdata/repomd.xml.sig", keyFile: "testdata/repomd_armored_public.pgp", verified: true},
		{caseDesc: "Valid V3 Signature, Incorrect Key", dataFile: "testdata/repomd.xml", sigFile: "testdata/repomd.xml.asc.sig", keyFile: "testdata/valid_armored_public.pgp", verified: false},
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
			t.Errorf("%v: unexpected result in verifying signature: %v", tc.caseDesc, err)
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
}

func TestVerifySkipsV3SignatureWithUnknownIssuer(t *testing.T) {
	knownV3, err := os.ReadFile("testdata/repomd.xml.sig")
	if err != nil {
		t.Fatal(err)
	}
	op, err := packet.NewOpaqueReader(bytes.NewReader(knownV3)).Next()
	if err != nil {
		t.Fatal(err)
	}
	// Change the issuer ID without changing the signed material, producing a
	// structurally valid signature from an issuer absent from the keyring.
	op.Contents[7] ^= 0xff
	var unknownV3 bytes.Buffer
	if err := op.Serialize(&unknownV3); err != nil {
		t.Fatal(err)
	}
	sigBytes := append(append([]byte(nil), unknownV3.Bytes()...), knownV3...)
	sig, err := NewSignature(bytes.NewReader(sigBytes))
	if err != nil {
		t.Fatal(err)
	}

	keyFile, err := os.Open("testdata/repomd_armored_public.pgp")
	if err != nil {
		t.Fatal(err)
	}
	defer keyFile.Close()
	key, err := NewPublicKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.Open("testdata/repomd.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	if err := sig.Verify(data, key); err != nil {
		t.Fatalf("verification did not skip the v3 signature with an unknown issuer: %v", err)
	}
}

func TestVerifySkipsV4SignatureWithUnknownIssuer(t *testing.T) {
	unknownV4, err := os.ReadFile("testdata/hello_world.txt.v4.sig")
	if err != nil {
		t.Fatal(err)
	}
	knownV3, err := os.ReadFile("testdata/repomd.xml.sig")
	if err != nil {
		t.Fatal(err)
	}
	sigBytes := append(append([]byte(nil), unknownV4...), knownV3...)
	sig, err := NewSignature(bytes.NewReader(sigBytes))
	if err != nil {
		t.Fatal(err)
	}

	keyFile, err := os.Open("testdata/repomd_armored_public.pgp")
	if err != nil {
		t.Fatal(err)
	}
	defer keyFile.Close()
	key, err := NewPublicKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.Open("testdata/repomd.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	if err := sig.Verify(data, key); err != nil {
		t.Fatalf("verification did not skip the v4 signature with an unknown issuer: %v", err)
	}
}

func TestVerifyV4AfterUnknownV3(t *testing.T) {
	unknownV3, err := os.ReadFile("testdata/repomd.xml.sig")
	if err != nil {
		t.Fatal(err)
	}
	op, err := packet.NewOpaqueReader(bytes.NewReader(unknownV3)).Next()
	if err != nil {
		t.Fatal(err)
	}
	op.Contents[7] ^= 0xff

	knownV4, err := os.ReadFile("testdata/hello_world.txt.v4.sig")
	if err != nil {
		t.Fatal(err)
	}
	var firstPacket bytes.Buffer
	if err := op.Serialize(&firstPacket); err != nil {
		t.Fatal(err)
	}
	sigBytes := append(append([]byte(nil), firstPacket.Bytes()...), knownV4...)
	sig, err := NewSignature(bytes.NewReader(sigBytes))
	if err != nil {
		t.Fatal(err)
	}

	keyFile, err := os.Open("testdata/valid_armored_public.pgp")
	if err != nil {
		t.Fatal(err)
	}
	defer keyFile.Close()
	key, err := NewPublicKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.Open("testdata/hello_world.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	if err := sig.Verify(data, key); err != nil {
		t.Fatalf("verification did not reach the v4 signature after an unknown v3 signature: %v", err)
	}
}

func TestVerifyV4UsesOwnCreationTime(t *testing.T) {
	keyTime := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	keyConfig := &packet.Config{
		Algorithm:       packet.PubKeyAlgoEdDSA,
		Time:            func() time.Time { return keyTime },
		KeyLifetimeSecs: 3600,
	}
	signer, err := openpgp.NewEntity("signer", "", "signer@example.com", keyConfig)
	if err != nil {
		t.Fatal(err)
	}
	unknownSigner, err := openpgp.NewEntity("unknown", "", "unknown@example.com", keyConfig)
	if err != nil {
		t.Fatal(err)
	}
	v3Bytes, err := os.ReadFile("testdata/repomd.xml.sig")
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("signed data")
	sign := func(t *testing.T, entity *openpgp.Entity, creationTime time.Time) []byte {
		t.Helper()
		var buf bytes.Buffer
		cfg := &packet.Config{Time: func() time.Time { return creationTime }}
		// Sign directly so the regression also exercises signatures made
		// after the signing key has expired.
		sig := &packet.Signature{
			Version:      4,
			SigType:      packet.SigTypeBinary,
			PubKeyAlgo:   entity.PrimaryKey.PubKeyAlgo,
			Hash:         crypto.SHA256,
			CreationTime: creationTime,
			IssuerKeyId:  &entity.PrimaryKey.KeyId,
		}
		h, err := sig.PrepareSign(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := sig.Sign(h, entity.PrivateKey, cfg); err != nil {
			t.Fatal(err)
		}
		if err := sig.Serialize(&buf); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}

	for _, tc := range []struct {
		name       string
		prefixTime time.Time
		signedTime time.Time
		wantErr    error
	}{
		{
			name:       "valid signature after expired prefix",
			prefixTime: keyTime.Add(2 * time.Hour),
			signedTime: keyTime.Add(time.Minute),
		},
		{
			name:       "expired key after valid prefix",
			prefixTime: keyTime.Add(time.Minute),
			signedTime: keyTime.Add(2 * time.Hour),
			wantErr:    pgperrors.ErrKeyExpired,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v3, err := packet.NewOpaqueReader(bytes.NewReader(v3Bytes)).Next()
			if err != nil {
				t.Fatal(err)
			}
			// The fixture's issuer is absent from the generated keyring. Its
			// timestamp must not affect verification of the following signature.
			binary.BigEndian.PutUint32(v3.Contents[3:7], uint32(tc.prefixTime.Unix()))
			var v3Prefix bytes.Buffer
			if err := v3.Serialize(&v3Prefix); err != nil {
				t.Fatal(err)
			}
			knownV4 := sign(t, signer, tc.signedTime)
			for name, prefix := range map[string][]byte{
				"unknown v3": v3Prefix.Bytes(),
				"unknown v4": sign(t, unknownSigner, tc.prefixTime),
			} {
				t.Run(name, func(t *testing.T) {
					body := append(append([]byte(nil), prefix...), knownV4...)
					sig, err := NewSignature(bytes.NewReader(body))
					if err != nil {
						t.Fatal(err)
					}
					err = sig.Verify(bytes.NewReader(data), &PublicKey{key: openpgp.EntityList{signer}})
					if !errors.Is(err, tc.wantErr) {
						t.Fatalf("Verify() error = %v, want %v", err, tc.wantErr)
					}
				})
			}
		})
	}
}

func TestVerifyReturnsUnknownIssuerAfterAllSignatures(t *testing.T) {
	sigFile, err := os.Open("testdata/repomd.xml.sig")
	if err != nil {
		t.Fatal(err)
	}
	defer sigFile.Close()
	sig, err := NewSignature(sigFile)
	if err != nil {
		t.Fatal(err)
	}

	keyFile, err := os.Open("testdata/valid_armored_public.pgp")
	if err != nil {
		t.Fatal(err)
	}
	defer keyFile.Close()
	key, err := NewPublicKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.Open("testdata/repomd.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	if err := sig.Verify(data, key); !errors.Is(err, pgperrors.ErrUnknownIssuer) {
		t.Fatalf("Verify() error = %v, want ErrUnknownIssuer", err)
	}
}

func TestVerifySkipsIgnoredPackets(t *testing.T) {
	knownV3, err := os.ReadFile("testdata/repomd.xml.sig")
	if err != nil {
		t.Fatal(err)
	}
	serialize := func(t *testing.T, op *packet.OpaquePacket) []byte {
		t.Helper()
		var buf bytes.Buffer
		if err := op.Serialize(&buf); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}

	unknownPacket := serialize(t, &packet.OpaquePacket{Tag: 60, Contents: []byte("ignored")})
	unsupportedSignature := serialize(t, &packet.OpaquePacket{Tag: 2, Contents: []byte{99}})
	unsupportedV3, err := packet.NewOpaqueReader(bytes.NewReader(knownV3)).Next()
	if err != nil {
		t.Fatal(err)
	}
	unsupportedV3.Contents[16] = 99
	unsupportedV3Packet := serialize(t, unsupportedV3)
	var marker bytes.Buffer
	if err := packet.SerializeMarker(&marker); err != nil {
		t.Fatal(err)
	}

	keyFile, err := os.Open("testdata/repomd_armored_public.pgp")
	if err != nil {
		t.Fatal(err)
	}
	defer keyFile.Close()
	key, err := NewPublicKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("testdata/repomd.xml")
	if err != nil {
		t.Fatal(err)
	}

	for name, prefix := range map[string][]byte{
		"unknown packet":        unknownPacket,
		"unsupported signature": unsupportedSignature,
		"unsupported v3 hash":   unsupportedV3Packet,
		"marker":                marker.Bytes(),
	} {
		t.Run(name, func(t *testing.T) {
			sigBytes := append(append([]byte(nil), prefix...), knownV3...)
			sig, err := NewSignature(bytes.NewReader(sigBytes))
			if err != nil {
				t.Fatal(err)
			}
			if err := sig.Verify(bytes.NewReader(data), key); err != nil {
				t.Fatalf("verification did not skip prefix packet: %v", err)
			}
		})
	}
}

func TestVerifyRejectsNonSignaturePacket(t *testing.T) {
	var body bytes.Buffer
	if err := (&packet.OpaquePacket{Tag: 13, Contents: []byte("user ID")}).Serialize(&body); err != nil {
		t.Fatal(err)
	}
	err := verifyDetached(nil, bytes.NewReader(nil), body.Bytes())
	if _, ok := errors.AsType[pgperrors.StructuralError](err); !ok {
		t.Fatalf("verifyDetached() error = %v, want StructuralError", err)
	}
}

func TestVerifyRejectsSignatureWithoutIssuer(t *testing.T) {
	contents, err := os.ReadFile("testdata/hello_world.txt.v4.sig")
	if err != nil {
		t.Fatal(err)
	}
	p, err := packet.Read(bytes.NewReader(contents))
	if err != nil {
		t.Fatal(err)
	}
	sig, ok := p.(*packet.Signature)
	if !ok {
		t.Fatalf("fixture contains %T, want *packet.Signature", p)
	}
	withoutIssuer := &packet.Signature{
		Version:      sig.Version,
		SigType:      sig.SigType,
		PubKeyAlgo:   sig.PubKeyAlgo,
		Hash:         sig.Hash,
		HashSuffix:   []byte{4, byte(sig.SigType), byte(sig.PubKeyAlgo), 8, 0, 0},
		HashTag:      sig.HashTag,
		CreationTime: sig.CreationTime,
		RSASignature: sig.RSASignature,
	}
	var body bytes.Buffer
	if err := withoutIssuer.Serialize(&body); err != nil {
		t.Fatal(err)
	}

	err = verifyDetached(nil, bytes.NewReader(nil), body.Bytes())
	if _, ok := errors.AsType[pgperrors.StructuralError](err); !ok {
		t.Fatalf("verifyDetached() error = %v, want StructuralError", err)
	}
}

func buildOversizedRSAPrivateKeyPacket(t *testing.T, tag uint8) []byte {
	t.Helper()
	writeMPI := func(buf *bytes.Buffer, b []byte) {
		bitLen := len(b) * 8
		_ = binary.Write(buf, binary.BigEndian, uint16(bitLen))
		buf.Write(b)
	}

	// Build a v4 unencrypted RSA secret-key packet with large MPIs so that if
	// it ever reached openpgp.ReadKeyRing -> parseRSAPrivateKey -> rsa.Validate,
	// it would trigger expensive modular exponentiation.
	var payload bytes.Buffer
	payload.WriteByte(4)                 // version 4
	payload.Write([]byte{0, 0, 0, 1})    // creation time
	payload.WriteByte(1)                 // RSA (Encrypt or Sign)
	n := bytes.Repeat([]byte{0x80}, 512) // 4096-bit even modulus
	e := []byte{0x01, 0x00, 0x01}        // 65537
	d := bytes.Repeat([]byte{0x81}, 512)
	p := bytes.Repeat([]byte{0x81}, 1024) // 8192-bit odd prime candidate
	q := bytes.Repeat([]byte{0x81}, 1024)
	u := []byte{0x01}
	writeMPI(&payload, n)
	writeMPI(&payload, e)
	payload.WriteByte(0) // s2k usage = 0 (unencrypted)

	var secret bytes.Buffer
	writeMPI(&secret, d)
	writeMPI(&secret, p)
	writeMPI(&secret, q)
	writeMPI(&secret, u)
	var sum uint16
	for _, b := range secret.Bytes() {
		sum += uint16(b)
	}
	payload.Write(secret.Bytes())
	_ = binary.Write(&payload, binary.BigEndian, sum)

	var pkt bytes.Buffer
	if err := (&packet.OpaquePacket{Tag: tag, Contents: payload.Bytes()}).Serialize(&pkt); err != nil {
		t.Fatal(err)
	}
	return pkt.Bytes()
}

func TestNewPublicKeyRejectsPrivateKeyPackets(t *testing.T) {
	privKeyPkt := buildOversizedRSAPrivateKeyPacket(t, packetTagPrivateKey)
	privSubkeyPkt := buildOversizedRSAPrivateKeyPacket(t, packetTagPrivateSubkey)

	validPub, err := os.ReadFile("testdata/valid_binary_public.pgp")
	if err != nil {
		t.Fatal(err)
	}

	var armoredAsPublic bytes.Buffer
	aw, err := armor.Encode(&armoredAsPublic, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aw.Write(privKeyPkt); err != nil {
		t.Fatal(err)
	}
	if err := aw.Close(); err != nil {
		t.Fatal(err)
	}

	// Prefixing a byte without MSB set mimics the OSS-Fuzz testcase where
	// openpgp.ReadKeyRing previously skipped past the invalid header via
	// readToNextPublicKey and parsed the following private key packet.
	corruptPrefixAndPriv := append([]byte{0x00}, privKeyPkt...)
	pubWithPrivSubkey := append(append([]byte(nil), validPub...), privSubkeyPkt...)

	// Smuggling a private key packet inside a streaming packet (e.g. old-format
	// indeterminate-length SymmetricallyEncrypted, tag 9, header byte 0xa7)
	// previously bypassed OpaqueReader's tag scan because OpaqueReader consumed
	// the entire body as one tag-9 packet while packet.Read left the body
	// unread for openpgp.ReadKeyRing to re-parse (OSS-Fuzz issue 588659662).
	indeterminateSymEncSmuggled := append([]byte{0xa7}, privKeyPkt...)

	var determinateSymEncSmuggled bytes.Buffer
	if err := (&packet.OpaquePacket{Tag: 9, Contents: privKeyPkt}).Serialize(&determinateSymEncSmuggled); err != nil {
		t.Fatal(err)
	}

	// Smuggling a private key packet in trailing bytes of a Marker packet
	// (tag 10), whose parser only reads the 3-byte "PGP" literal.
	var markerTrailingSmuggled bytes.Buffer
	if err := (&packet.OpaquePacket{Tag: 10, Contents: append([]byte("PGP"), privKeyPkt...)}).Serialize(&markerTrailingSmuggled); err != nil {
		t.Fatal(err)
	}

	// Smuggling a private key packet in trailing bytes of a PublicKey packet
	// (tag 6).
	firstPubPkt, err := packet.NewOpaqueReader(bytes.NewReader(validPub)).Next()
	if err != nil {
		t.Fatal(err)
	}
	var pubKeyTrailingSmuggled bytes.Buffer
	if err := (&packet.OpaquePacket{
		Tag:      firstPubPkt.Tag,
		Contents: append(append([]byte(nil), firstPubPkt.Contents...), privKeyPkt...),
	}).Serialize(&pubKeyTrailingSmuggled); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		input []byte
	}{
		{name: "binary private key packet", input: privKeyPkt},
		{name: "private key packet inside armored public key block", input: armoredAsPublic.Bytes()},
		{name: "corrupt header followed by private key packet", input: corruptPrefixAndPriv},
		{name: "valid public key followed by private subkey packet", input: pubWithPrivSubkey},
		{name: "private key packet smuggled in indeterminate symmetrically encrypted packet", input: indeterminateSymEncSmuggled},
		{name: "private key packet smuggled in determinate symmetrically encrypted packet", input: determinateSymEncSmuggled.Bytes()},
		{name: "private key packet smuggled in trailing bytes of marker packet", input: markerTrailingSmuggled.Bytes()},
		{name: "private key packet smuggled in trailing bytes of public key packet", input: pubKeyTrailingSmuggled.Bytes()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			got, err := NewPublicKey(bytes.NewReader(tc.input))
			elapsed := time.Since(start)
			if err == nil || got != nil {
				t.Fatalf("NewPublicKey() = (%v, %v), want error", got, err)
			}
			if elapsed > time.Second {
				t.Fatalf("NewPublicKey() took %v, expected immediate rejection", elapsed)
			}
		})
	}
}

func TestNewSignatureRejectsPrivateKeyPackets(t *testing.T) {
	privKeyPkt := buildOversizedRSAPrivateKeyPacket(t, packetTagPrivateKey)
	privSubkeyPkt := buildOversizedRSAPrivateKeyPacket(t, packetTagPrivateSubkey)

	var armoredAsSig bytes.Buffer
	aw, err := armor.Encode(&armoredAsSig, openpgp.SignatureType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aw.Write(privKeyPkt); err != nil {
		t.Fatal(err)
	}
	if err := aw.Close(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		input []byte
	}{
		{name: "binary private key packet", input: privKeyPkt},
		{name: "binary private subkey packet", input: privSubkeyPkt},
		{name: "private key packet inside armored signature block", input: armoredAsSig.Bytes()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			got, err := NewSignature(bytes.NewReader(tc.input))
			elapsed := time.Since(start)
			if err == nil || got != nil {
				t.Fatalf("NewSignature() = (%v, %v), want error", got, err)
			}
			if _, ok := errors.AsType[pgperrors.StructuralError](err); !ok {
				t.Fatalf("NewSignature() error = %v, want StructuralError", err)
			}
			if elapsed > time.Second {
				t.Fatalf("NewSignature() took %v, expected immediate rejection", elapsed)
			}
		})
	}
}
