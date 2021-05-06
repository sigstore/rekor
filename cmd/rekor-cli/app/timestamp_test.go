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
		request               string
		file                  string
		expectParseSuccess    bool
		expectValidateSuccess bool
		expectRequestSuccess  bool
	}

	tests := []test{
		{
			caseDesc:              "valid local file",
			file:                  "../../../tests/test_file.txt",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
			expectRequestSuccess:  true,
		},
		{
			caseDesc:              "nonexistant local file",
			file:                  "../../../tests/not_a_file",
			expectParseSuccess:    false,
			expectValidateSuccess: false,
			expectRequestSuccess:  false,
		},
		{
			caseDesc:              "valid request file",
			request:               "../../../tests/test_request.tsq",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
			expectRequestSuccess:  true,
		},
		{
			caseDesc:              "nonexistant request file",
			file:                  "../../../tests/not_a_request",
			expectParseSuccess:    false,
			expectValidateSuccess: false,
			expectRequestSuccess:  false,
		},
		{
			caseDesc:              "no request or file specified",
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

		if tc.request != "" {
			args = append(args, "--request", tc.request)
		}
		if tc.file != "" {
			args = append(args, "--file", tc.file)
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
