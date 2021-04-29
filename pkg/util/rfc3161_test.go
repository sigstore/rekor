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
	"io/ioutil"
	"testing"

	"github.com/sassoftware/relic/lib/x509tools"
)

func TestCreateTimestampRequest(t *testing.T) {
	type TestCase struct {
		caseDesc      string
		entry         []byte
		expectSuccess bool
	}

	fileBytes, _ := ioutil.ReadFile("../../tests/test_file.txt")
	testCases := []TestCase{
		{
			caseDesc:      "valid timestamp request",
			entry:         fileBytes,
			expectSuccess: true,
		},
	}
	for _, tc := range testCases {
		req, err := TimestampRequestFromData(tc.entry)
		if (err == nil) != tc.expectSuccess {
			t.Errorf("unexpected error in test case '%v': %v", tc.caseDesc, err)
		}
		// Validate request.
		hash, _ := x509tools.PkixDigestToHash(req.MessageImprint.HashAlgorithm)
		h := hash.New()
		h.Write(fileBytes)
		digest := h.Sum(nil)
		if !bytes.Equal(digest, req.MessageImprint.HashedMessage) {
			t.Errorf("unexpected error in test case '%v': %v", tc.caseDesc, err)
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
