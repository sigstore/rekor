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

package types

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/tidwall/sjson"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

type BadReader struct {
}

func (br BadReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("test error")
}

func jsonSetNoError(input, path string, value interface{}) string {
	ret, _ := sjson.Set(input, path, value)
	return ret
}

func jsonDeleteNoError(input, path string) string {
	ret, _ := sjson.Delete(input, path)
	return ret
}

func TestRekorLeaf(t *testing.T) {

	type Test struct {
		caseDesc      string
		json          string
		expectSuccess bool
	}

	kernelJSONBytes, _ := ioutil.ReadFile("../../tests/kernel.json")
	originalEntry := string(kernelJSONBytes)
	originalLeaf := jsonDeleteNoError(originalEntry, "URL")

	tests := []Test{
		{
			caseDesc:      "Valid full entry",
			json:          originalEntry,
			expectSuccess: true,
		},
		{
			caseDesc:      "Valid full leaf",
			json:          originalLeaf,
			expectSuccess: true,
		},
		{
			caseDesc:      "Valid leaf without SHA",
			json:          jsonDeleteNoError(originalLeaf, "SHA"),
			expectSuccess: true,
		},
		{
			caseDesc:      "Invalid SHA",
			json:          jsonSetNoError(originalLeaf, "SHA", "not_a_valid_sha_hash!!!"),
			expectSuccess: false,
		},
		{
			caseDesc:      "Invalid signature",
			json:          jsonSetNoError(originalLeaf, "Signature", "not_a_signature!!!"),
			expectSuccess: false,
		},
		{
			caseDesc:      "Invalid public key",
			json:          jsonSetNoError(originalLeaf, "PublicKey", "c29tZV9kYXRhCg=="),
			expectSuccess: false,
		},
		{
			caseDesc:      "Missing signature",
			json:          jsonDeleteNoError(originalLeaf, "Signature"),
			expectSuccess: false,
		},
		{
			caseDesc:      "Missing public key",
			json:          jsonDeleteNoError(originalLeaf, "PublicKey"),
			expectSuccess: false,
		},
		{
			caseDesc:      "Invalid JSON",
			json:          `This is not valid JSON!`,
			expectSuccess: false,
		},
		{
			caseDesc:      "Empty JSON",
			json:          `{}`,
			expectSuccess: false,
		},
	}

	for _, tc := range tests {
		leaf, err := ParseRekorLeaf(strings.NewReader(tc.json))
		if (err == nil) != tc.expectSuccess {
			t.Errorf("Error in test case '%v': %v", tc.caseDesc, err)
		}

		if tc.expectSuccess == true {
			jsonMap := make(map[string]string)
			err := json.Unmarshal([]byte(tc.json), &jsonMap)
			if err != nil {
				t.Errorf("Error in test case '%v' comparing leaf to input: %v", tc.caseDesc, err)
			}
			for key, val := range jsonMap {
				if key == "SHA" {
					if val != reflect.Indirect(reflect.ValueOf(leaf)).FieldByName(key).String() {
						t.Errorf("Error in test case '%v': leaf does not reflect input for '%v'", tc.caseDesc, key)
					}
				} else if key == "Signature" || key == "PublicKey" {
					leafVal := base64.StdEncoding.EncodeToString(reflect.Indirect(reflect.ValueOf(leaf)).FieldByName(key).Bytes())
					if val != leafVal {
						t.Errorf("Error in test case '%v': leaf does not reflect input for '%v' %v != %v", tc.caseDesc, key, val, leafVal)
					}
				}
			}
		}
	}

	if _, err := ParseRekorLeaf(&BadReader{}); err == nil {
		t.Errorf("No error thrown if io.Reader failed")
	}
}

func TestRekorEntry(t *testing.T) {
	type Test struct {
		caseDesc      string
		json          string
		leaf          *RekorLeaf
		expectSuccess bool
	}

	kernelJSONBytes, _ := ioutil.ReadFile("../../tests/kernel.json")
	originalEntry := string(kernelJSONBytes)

	tests := []Test{
		{
			caseDesc:      "Valid full entry with URL & SHA",
			json:          originalEntry,
			leaf:          nil,
			expectSuccess: true,
		},
		{
			caseDesc:      "Valid full entry with Data",
			json:          jsonSetNoError(jsonDeleteNoError(jsonDeleteNoError(originalEntry, "URL"), "SHA"), "Data", "c29tZV9kYXRhCg=="),
			leaf:          nil,
			expectSuccess: true,
		},
		{
			caseDesc:      "Invalid entry without URL or Data",
			json:          jsonDeleteNoError(originalEntry, "URL"),
			leaf:          nil,
			expectSuccess: false,
		},
		{
			caseDesc:      "Invalid entry with URL but no SHA",
			json:          jsonDeleteNoError(originalEntry, "SHA"),
			leaf:          nil,
			expectSuccess: false,
		},
		{
			caseDesc:      "Invalid entry with bad URL",
			json:          jsonSetNoError(originalEntry, "URL", "not_a_url"),
			leaf:          nil,
			expectSuccess: false,
		},
		{
			caseDesc:      "Valid entry but empty leaf",
			json:          originalEntry,
			leaf:          &RekorLeaf{},
			expectSuccess: false,
		},
	}

	for _, tc := range tests {
		if tc.leaf == nil {
			leaf, err := ParseRekorLeaf(strings.NewReader(tc.json))
			if err != nil {
				t.Errorf("unexpected error in '%v': %v", tc.caseDesc, err)
			}
			tc.leaf = &leaf
		}

		if _, err := ParseRekorEntry(strings.NewReader(tc.json), *(tc.leaf)); (err == nil) != tc.expectSuccess {
			t.Errorf("Error in test case '%v': %v", tc.caseDesc, err)
		}
	}

	if _, err := ParseRekorEntry(&BadReader{}, RekorLeaf{}); err == nil {
		t.Errorf("No error thrown if io.Reader failed")
	}

	// valid leaf, invalid JSON
	leaf, err := ParseRekorLeaf(strings.NewReader(tests[0].json))
	if err != nil {
		t.Errorf("unexpected error in '%v': %v", tests[0].caseDesc, err)
	}

	if _, err := ParseRekorEntry(strings.NewReader("not json"), leaf); err == nil {
		t.Errorf("No error thrown for invalid JSON but valid leaf")
	}
}

func TestRekorLoad(t *testing.T) {
	type Test struct {
		caseDesc      string
		entry         *RekorEntry
		expectSuccess bool
	}

	validLeafBytes, _ := ioutil.ReadFile("../../tests/kernel.json")
	validLeaf, _ := ParseRekorLeaf(bytes.NewReader(validLeafBytes))

	smallValidFileBytes, _ := ioutil.ReadFile("../../tests/test_file.txt")
	smallValidLeafBytes, _ := ioutil.ReadFile("../../tests/rekor.json")
	smallValidLeaf, _ := ParseRekorLeaf(bytes.NewReader(smallValidLeafBytes))

	gzipValidFile := new(bytes.Buffer)
	gzipW := gzip.NewWriter(gzipValidFile)
	_, _ = gzipW.Write(smallValidFileBytes)
	gzipW.Close()

	testServer := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path[1:] == "premature_close" {
				return
			}
			if r.URL.Path[1:] == "not_found" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.URL.Path[1:] == "invalidFile" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("doesn't match"))
			}
			if r.URL.Path[1:] == "smallValidFile" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(smallValidFileBytes)
			}
			if r.URL.Path[1:] == "gzipValidFile" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(gzipValidFile.Bytes())
			}
		}))
	defer testServer.Close()

	tests := []Test{
		{
			caseDesc:      "Invalid entry",
			entry:         &RekorEntry{},
			expectSuccess: false,
		},
		{
			caseDesc: "Invalid URL",
			entry: &RekorEntry{
				nil,
				"not_a_url",
				RekorLeaf{validLeaf.SHA, validLeaf.Signature, validLeaf.PublicKey, nil, nil},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "HTTP Server Closes Prematurely",
			entry: &RekorEntry{
				nil,
				testServer.URL + "/premature_close",
				RekorLeaf{validLeaf.SHA, validLeaf.Signature, validLeaf.PublicKey, nil, nil},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "HTTP Server 404 not found",
			entry: &RekorEntry{
				nil,
				testServer.URL + "/not_found",
				RekorLeaf{validLeaf.SHA, validLeaf.Signature, validLeaf.PublicKey, nil, nil},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "Valid small file (to test content_type detection lower limit",
			entry: &RekorEntry{
				nil,
				testServer.URL + "/smallValidFile",
				RekorLeaf{smallValidLeaf.SHA, smallValidLeaf.Signature, smallValidLeaf.PublicKey, nil, nil},
			},
			expectSuccess: true,
		},
		{
			caseDesc: "Valid file with mismatched SHA value",
			entry: &RekorEntry{
				nil,
				testServer.URL + "/smallValidFile",
				RekorLeaf{"1" + smallValidLeaf.SHA[1:], smallValidLeaf.Signature, smallValidLeaf.PublicKey, nil, nil},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "Valid file with failed signature validation",
			entry: &RekorEntry{
				nil,
				testServer.URL + "/invalidFile",
				RekorLeaf{validLeaf.SHA, validLeaf.Signature, validLeaf.PublicKey, nil, nil},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "Valid gzipped file",
			entry: &RekorEntry{
				nil,
				testServer.URL + "/gzipValidFile",
				RekorLeaf{smallValidLeaf.SHA, smallValidLeaf.Signature, smallValidLeaf.PublicKey, nil, nil},
			},
			expectSuccess: true,
		},
		{
			caseDesc: "Valid file passed in through Data field",
			entry: &RekorEntry{
				smallValidFileBytes,
				"",
				RekorLeaf{"", smallValidLeaf.Signature, smallValidLeaf.PublicKey, nil, nil},
			},
			expectSuccess: true,
		},
	}

	for _, tc := range tests {
		ctx := context.TODO()
		beforeSHA := tc.entry.SHA
		if err := tc.entry.Load(ctx); (err == nil) != tc.expectSuccess {
			t.Errorf("Error in test case '%v': %v", tc.caseDesc, err)
		}
		if tc.expectSuccess && beforeSHA == "" && tc.entry.SHA == "" {
			t.Errorf("Error in test case '%v': SHA not set after call to Load()", tc.caseDesc)
		}
	}
}

func TestRekorLeafMarshalJSON(t *testing.T) {
	type Test struct {
		caseDesc      string
		leaf          *RekorLeaf
		expectSuccess bool
	}

	validLeafBytes, _ := ioutil.ReadFile("../../tests/kernel.json")
	validLeaf, _ := ParseRekorLeaf(bytes.NewReader(validLeafBytes))

	tests := []Test{
		{
			caseDesc:      "Valid Leaf",
			leaf:          &RekorLeaf{validLeaf.SHA, validLeaf.Signature, validLeaf.PublicKey, nil, nil},
			expectSuccess: true,
		},
		{
			caseDesc:      "Invalid Leaf, bad sig",
			leaf:          &RekorLeaf{validLeaf.SHA, []byte("not a sig"), validLeaf.PublicKey, nil, nil},
			expectSuccess: false,
		},
		{
			caseDesc:      "Invalid Leaf, bad key",
			leaf:          &RekorLeaf{validLeaf.SHA, validLeaf.Signature, []byte("not a key"), nil, nil},
			expectSuccess: false,
		},
		{
			caseDesc:      "Invalid Leaf, empty",
			leaf:          &RekorLeaf{},
			expectSuccess: false,
		},
	}

	for _, tc := range tests {
		_ = tc.leaf.ValidateLeaf()
		jsonOutput, err := json.Marshal(tc.leaf)
		if (err == nil) != tc.expectSuccess {
			t.Errorf("Error in test case '%v': %v", tc.caseDesc, err)
		}
		if tc.expectSuccess {
			var marshalledLeaf RekorLeaf
			if err := json.Unmarshal(jsonOutput, &marshalledLeaf); err != nil {
				t.Errorf("Error in test case '%v': unable to unmarshal JSON returned", tc.caseDesc)
			}
			if tc.leaf.SHA != marshalledLeaf.SHA {
				t.Errorf("Error in test case '%v': output SHA in JSON did not match input", tc.caseDesc)
			}
		}
	}
}
