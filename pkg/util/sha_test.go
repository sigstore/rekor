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
	"crypto"
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
		{
			input: "78674b244bc9cba8ecb6dcb660b059728236e36b2f30fbcd6e17b1b64255f3ac596fbe5c84d1cc9d2a0979513260de09",
			want:  "sha384:78674b244bc9cba8ecb6dcb660b059728236e36b2f30fbcd6e17b1b64255f3ac596fbe5c84d1cc9d2a0979513260de09",
		},
	}

	for _, tr := range testCases {
		got := PrefixSHA(tr.input)
		if got != tr.want {
			t.Errorf("Got '%s' expected '%s'", got, tr.want)
		}
	}
}

func TestUnprefixSHA(t *testing.T) {
	type prefixedSHA struct {
		crypto.Hash
		string
	}
	var testCases = []struct {
		input string
		want  prefixedSHA
	}{
		{
			input: "87428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7",
			want: prefixedSHA{
				crypto.SHA256,
				"87428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7",
			},
		},
		{
			input: "sha512:162b0b32f02482d5aca0a7c93dd03ceac3acd7e410a5f18f3fb990fc958ae0df6f32233b91831eaf99ca581a8c4ddf9c8ba315ac482db6d4ea01cc7884a635be",
			want: prefixedSHA{
				crypto.SHA512,
				"162b0b32f02482d5aca0a7c93dd03ceac3acd7e410a5f18f3fb990fc958ae0df6f32233b91831eaf99ca581a8c4ddf9c8ba315ac482db6d4ea01cc7884a635be",
			},
		},
		{
			input: "09b80428c53912d4174162fd5b7c7d485bdcc3ab",
			want: prefixedSHA{
				crypto.SHA1,
				"09b80428c53912d4174162fd5b7c7d485bdcc3ab",
			},
		},
		{
			input: "cfd356237e261871e8f92ae6710a75a65a925ae121d94d28533f008bd3e00b5472d261b5d0e1ab4082e3078dd1ad2af57876ed3c1c797c4097dbed870f458408",
			want: prefixedSHA{
				crypto.SHA512,
				"cfd356237e261871e8f92ae6710a75a65a925ae121d94d28533f008bd3e00b5472d261b5d0e1ab4082e3078dd1ad2af57876ed3c1c797c4097dbed870f458408",
			},
		},
		{
			input: "78674b244bc9cba8ecb6dcb660b059728236e36b2f30fbcd6e17b1b64255f3ac596fbe5c84d1cc9d2a0979513260de09",
			want: prefixedSHA{
				crypto.SHA384,
				"78674b244bc9cba8ecb6dcb660b059728236e36b2f30fbcd6e17b1b64255f3ac596fbe5c84d1cc9d2a0979513260de09",
			},
		},
		{
			input: "sha384:78674b244bc9cba8ecb6dcb660b059728236e36b2f30fbcd6e17b1b64255f3ac596fbe5c84d1cc9d2a0979513260de09",
			want: prefixedSHA{
				crypto.SHA384,
				"78674b244bc9cba8ecb6dcb660b059728236e36b2f30fbcd6e17b1b64255f3ac596fbe5c84d1cc9d2a0979513260de09",
			},
		},
	}

	for _, tr := range testCases {
		algo, value := UnprefixSHA(tr.input)
		got := prefixedSHA{algo, value}
		if got != tr.want {
			t.Errorf("Got '%v' expected '%v' (input %s)", got, tr.want, tr.input)
		}
	}
}
