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

func TestPrefixSHA(t *testing.T) {
	var testCases = []struct {
		input string
		want  string
	}{
		{
			input: "123",
			want:  "123",
		},
		{
			input: "sha512:abc",
			want:  "sha512:abc",
		},
		{
			input: "09b80428c53912d4174162fd5b7c7d485bdcc3ab",
			want:  "sha1:09b80428c53912d4174162fd5b7c7d485bdcc3ab",
		},
		{
			input: "b9869be95b24001702120dd5dd673a9bd8447446fb57220388d8d0a48c738808",
			want:  "sha256:b9869be95b24001702120dd5dd673a9bd8447446fb57220388d8d0a48c738808",
		},
		{
			input: "cfd356237e261871e8f92ae6710a75a65a925ae121d94d28533f008bd3e00b5472d261b5d0e1ab4082e3078dd1ad2af57876ed3c1c797c4097dbed870f458408",
			want:  "sha512:cfd356237e261871e8f92ae6710a75a65a925ae121d94d28533f008bd3e00b5472d261b5d0e1ab4082e3078dd1ad2af57876ed3c1c797c4097dbed870f458408",
		},
	}

	for _, tr := range testCases {
		got := PrefixSHA(tr.input)
		if got != tr.want {
			t.Errorf("Got '%s' expected '%s'", got, tr.want)
		}
	}
}
