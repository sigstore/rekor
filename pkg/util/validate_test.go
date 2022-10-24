//
// Copyright 2022 The Sigstore Authors.
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
	"testing"
)

func TestSHA1(t *testing.T) {
	var tests = []struct {
		value      string
		expectFail bool
	}{
		{
			value:      "",
			expectFail: true,
		},
		// to short
		{
			value:      "sha1:7c65d0f10d62751f84469873d6c595423eee8b0",
			expectFail: true,
		},
		// too long
		{
			value:      "7c65d0f10d62751f84469873d6c595423eee8b078",
			expectFail: true,
		},
		// invalid char g
		{
			value:      "gc65d0f10d62751f84469873d6c595423eee8c07",
			expectFail: true,
		},
		{
			value:      "sha1:ac65d0f10d62751f84469873d6c595423eee8c07",
			expectFail: false,
		},
		{
			value:      "AC65d0f10d62751f84469873d6c595423eee8c07",
			expectFail: false,
		},
	}

	for _, tr := range tests {
		err := ValidateSHA1Value(tr.value)
		if tr.expectFail == (err == nil) {
			t.Errorf("Failure validating '%s': %s", tr.value, err)
		}
	}
}

func TestSHA256(t *testing.T) {
	var tests = []struct {
		value      string
		expectFail bool
	}{
		{
			value:      "",
			expectFail: true,
		},
		// to short
		{
			value:      "sha256:db1abb0bc57a17623cf1181f67b922fc6b868eee27ae81e43efeba68a2002ec",
			expectFail: true,
		},
		// too long
		{
			value:      "db1abb0bc57a17623cf1181f67b922fc6b868eee27ae81e43efeba68a2002ec5fa",
			expectFail: true,
		},
		// invalid char g
		{
			value:      "gb1abb0bc57a17623cf1181f67b922fc6b868eee27ae81e43efeba68a2002ec5",
			expectFail: true,
		},
		{
			value:      "sha256:db1abb0bc57a17623cf1181f67b922fc6b868eee27ae81e43efeba68a2002ec5",
			expectFail: false,
		},
		{
			value:      "DB1abb0bc57a17623cf1181f67b922fc6b868eee27ae81e43efeba68a2002ec5",
			expectFail: false,
		},
	}

	for _, tr := range tests {
		err := ValidateSHA256Value(tr.value)
		if tr.expectFail == (err == nil) {
			t.Errorf("Failure validating '%s': %s", tr.value, err)
		}
	}
}

func TestSHA512(t *testing.T) {
	var tests = []struct {
		value      string
		expectFail bool
	}{
		{
			value:      "",
			expectFail: true,
		},
		// to short
		{
			value:      "sha512:6ae8d43391b2adb187e211a7619d11e8f696321cf5e9266ab51423e79d5974cbc679cd8ad15431b32b4d3ed53a6da3be446dd5bb270defe5f4e940fc018040c",
			expectFail: true,
		},
		// too long
		{
			value:      "6ae8d43391b2adb187e211a7619d11e8f696321cf5e9266ab51423e79d5974cbc679cd8ad15431b32b4d3ed53a6da3be446dd5bb270defe5f4e940fc018040c71",
			expectFail: true,
		},
		// invalid char h
		{
			value:      "hae8d43391b2adb187e211a7619d11e8f696321cf5e9266ab51423e79d5974cbc679cd8ad15431b32b4d3ed53a6da3be446dd5bb270defe5f4e940fc018040c7",
			expectFail: true,
		},
		{
			value:      "sha512:6ae8d43391b2adb187e211a7619d11e8f696321cf5e9266ab51423e79d5974cbc679cd8ad15431b32b4d3ed53a6da3be446dd5bb270defe5f4e940fc018040c7",
			expectFail: false,
		},
		{
			value:      "ABe8d43391b2adb187e211a7619d11e8f696321cf5e9266ab51423e79d5974cbc679cd8ad15431b32b4d3ed53a6da3be446dd5bb270defe5f4e940fc018040c7",
			expectFail: false,
		},
	}

	for _, tr := range tests {
		err := ValidateSHA512Value(tr.value)
		if tr.expectFail == (err == nil) {
			t.Errorf("Failure validating '%s': %s", tr.value, err)
		}
	}
}
