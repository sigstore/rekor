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

package app

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func TestTimestampFlags(t *testing.T) {
	type test struct {
		caseDesc              string
		artifact              string
		artifactHash          string
		oid                   string
		expectParseSuccess    bool
		expectValidateSuccess bool
		expectRequestSuccess  bool
	}

	tests := []test{
		{
			caseDesc:              "valid local artifact",
			artifact:              "../../../tests/test_file.txt",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
			expectRequestSuccess:  true,
		},
		{
			caseDesc:              "nonexistant local artifact",
			artifact:              "../../../tests/not_a_file",
			expectParseSuccess:    false,
			expectValidateSuccess: false,
			expectRequestSuccess:  false,
		},
		{
			caseDesc:              "valid artifact hash",
			artifactHash:          "45c7b11fcbf07dec1694adecd8c5b85770a12a6c8dfdcf2580a2db0c47c31779",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
			expectRequestSuccess:  true,
		},
		{
			caseDesc:              "invalid artifact hash",
			artifactHash:          "aaa",
			expectParseSuccess:    false,
			expectValidateSuccess: false,
			expectRequestSuccess:  false,
		},
		{
			caseDesc:              "nonexistant request artifact",
			artifact:              "../../../tests/not_a_request",
			expectParseSuccess:    false,
			expectValidateSuccess: false,
			expectRequestSuccess:  false,
		},
		{
			caseDesc:              "valid oid",
			artifact:              "../../../tests/test_file.txt",
			oid:                   "1.2.3.4",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
			expectRequestSuccess:  true,
		},
		{
			caseDesc:              "invalid oid",
			artifact:              "../../../tests/test_file.txt",
			oid:                   "1.a.3.4",
			expectParseSuccess:    false,
			expectValidateSuccess: true,
			expectRequestSuccess:  true,
		},
		{
			caseDesc:              "no request or artifact specified",
			expectParseSuccess:    true,
			expectValidateSuccess: false,
			expectRequestSuccess:  false,
		},
	}

	for _, tc := range tests {
		var blankCmd = &cobra.Command{}
		if err := addTimestampFlags(blankCmd); err != nil {
			t.Fatalf("unexpected error adding flags in '%v': %v", tc.caseDesc, err)
		}

		args := []string{}

		if tc.artifact != "" {
			args = append(args, "--artifact", tc.artifact)
		}
		if tc.artifactHash != "" {
			args = append(args, "--artifact-hash", tc.artifactHash)
		}
		if tc.oid != "" {
			args = append(args, "--tsa-policy", tc.oid)
		}
		if err := blankCmd.ParseFlags(args); (err == nil) != tc.expectParseSuccess {
			t.Errorf("unexpected result parsing '%v': %v", tc.caseDesc, err)
			continue
		}

		if err := viper.BindPFlags(blankCmd.Flags()); err != nil {
			t.Fatalf("unexpected result initializing viper in '%v': %v", tc.caseDesc, err)
		}
		if err := validateTimestampFlags(); (err == nil) != tc.expectValidateSuccess {
			t.Errorf("unexpected result validating '%v': %v", tc.caseDesc, err)
			continue
		}
		if _, err := createRequestFromFlags(); (err == nil) != tc.expectRequestSuccess {
			t.Errorf("unexpected result creating timestamp request '%v': %v", tc.caseDesc, err)
			continue
		}
	}
}
