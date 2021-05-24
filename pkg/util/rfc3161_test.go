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

package util

import (
	"bytes"
	"context"
	"crypto"
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"math/big"
	"testing"

	"github.com/sassoftware/relic/lib/pkcs9"
	"github.com/sassoftware/relic/lib/x509tools"
	"github.com/sigstore/rekor/pkg/signer"
)

func TestCreateTimestampRequest(t *testing.T) {
	type TestCase struct {
		caseDesc      string
		entry         []byte
		expectSuccess bool
		nonce         *big.Int
		policy        asn1.ObjectIdentifier
	}

	fileBytes, _ := ioutil.ReadFile("../../tests/test_file.txt")
	testCases := []TestCase{
		{
			caseDesc:      "valid timestamp request",
			entry:         fileBytes,
			expectSuccess: true,
			nonce:         x509tools.MakeSerial(),
		},
		{
			caseDesc:      "valid timestamp request no nonce",
			entry:         fileBytes,
			expectSuccess: true,
		},
		{
			caseDesc:      "valid timestamp request with TSA policy id",
			entry:         fileBytes,
			expectSuccess: true,
			policy:        asn1.ObjectIdentifier{1, 2, 3, 4, 5},
		},
	}
	for _, tc := range testCases {
		opts := TimestampRequestOptions{
			Hash:         crypto.SHA256,
			Nonce:        tc.nonce,
			TSAPolicyOid: tc.policy,
		}
		h := opts.Hash.New()
		h.Write(tc.entry)
		digest := h.Sum(nil)
		req, err := TimestampRequestFromDigest(digest, opts)
		if (err == nil) != tc.expectSuccess {
			t.Errorf("unexpected error in test case '%v': %v", tc.caseDesc, err)
		}
		// Validate that the message hash matches the original file has.
		if !bytes.Equal(digest, req.MessageImprint.HashedMessage) {
			t.Errorf("unexpected error in test case '%v': %v", tc.caseDesc, "hashes do not match")
		}
		if tc.nonce != nil {
			if tc.nonce.Cmp(req.Nonce) != 0 {
				t.Errorf("unexpected error in test case '%v': %v", tc.caseDesc, "nonce does not match")
			}
		} else if req.Nonce != nil {
			t.Errorf("unexpected error in test case '%v': %v", tc.caseDesc, fmt.Sprintf("nonce does not match got (%s) expected nil", req.Nonce.String()))
		}
		if tc.policy != nil {
			if !tc.policy.Equal(req.ReqPolicy) {
				t.Errorf("unexpected error in test case '%v': %v", tc.caseDesc, "policy does not match")
			}
		} else if req.ReqPolicy != nil {
			t.Errorf("unexpected error in test case '%v': %v", tc.caseDesc, "policy does not match")
		}
	}
}

func TestParseTimestampRequest(t *testing.T) {
	type TestCase struct {
		caseDesc      string
		entry         []byte
		expectSuccess bool
	}

	requestBytes, _ := ioutil.ReadFile("../../tests/test_request.tsq")
	fileBytes, _ := ioutil.ReadFile("../../tests/test_file.txt")

	testCases := []TestCase{
		{
			caseDesc:      "valid timestamp request",
			entry:         requestBytes,
			expectSuccess: true,
		},
		{
			caseDesc:      "invalid timestamp request",
			entry:         fileBytes,
			expectSuccess: false,
		},
	}

	for _, tc := range testCases {
		if _, err := ParseTimestampRequest(tc.entry); (err == nil) != tc.expectSuccess {
			t.Errorf("unexpected error in test case '%v': %v", tc.caseDesc, err)
		}
	}
}

// Create an in-memory CA and TSA and verify the response.
func TestCreateRFC3161Response(t *testing.T) {
	ctx := context.Background()
	mem, err := signer.NewMemory()
	if err != nil {
		t.Error(err)
	}
	pk, err := mem.PublicKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	certChain, err := signer.NewTimestampingCertWithSelfSignedCA(pk)
	if err != nil {
		t.Error(err)
	}

	fileBytes, _ := ioutil.ReadFile("../../tests/test_file.txt")
	opts := TimestampRequestOptions{
		Hash:  crypto.SHA256,
		Nonce: x509tools.MakeSerial(),
	}
	h := opts.Hash.New()
	h.Write(fileBytes)
	digest := h.Sum(nil)
	req, err := TimestampRequestFromDigest(digest, opts)
	if err != nil {
		t.Error(err)
	}

	resp, err := CreateRfc3161Response(ctx, *req, certChain, mem)
	if err != nil {
		t.Error(err)
	}

	_, err = pkcs9.Verify(&resp.TimeStampToken, fileBytes, certChain)
	if err != nil {
		t.Error(err)
	}
}
