/*
Copyright © 2021 The Sigstore Authors.

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

package tuf

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/swag"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/verify"

	"go.uber.org/goleak"
)

func patchIsExpired() func() {
	// Patch out the IsExpired to make the tests stable :)
	old := verify.IsExpired
	verify.IsExpired = func(_ time.Time) bool {
		return false
	}
	return func() {
		verify.IsExpired = old
	}
}

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestNewEntryReturnType(t *testing.T) {
	entry := NewEntry()
	if reflect.TypeOf(entry) != reflect.ValueOf(&V001Entry{}).Type() {
		t.Errorf("invalid type returned from NewEntry: %T", entry)
	}
}

func TestCrossFieldValidation(t *testing.T) {
	defer patchIsExpired()()

	type TestCase struct {
		caseDesc                  string
		entry                     V001Entry
		expectUnmarshalSuccess    bool
		expectCanonicalizeSuccess bool
		expectVerifierSuccess     bool
	}

	keyBytes, _ := os.ReadFile("tests/test_root.json")
	dataBytes, _ := os.ReadFile("tests/test_timestamp.json")
	anyBytes, _ := os.ReadFile("tests/test_any.json")

	keyContent := &data.Signed{}
	if err := json.Unmarshal(keyBytes, keyContent); err != nil {
		t.Errorf("unexpected error")
	}
	dataContent := &data.Signed{}
	if err := json.Unmarshal(dataBytes, dataContent); err != nil {
		t.Errorf("unexpected error")
	}
	anyContent := &data.Signed{}
	if err := json.Unmarshal(anyBytes, anyContent); err != nil {
		t.Errorf("unexpected error")
	}

	testCases := []TestCase{
		{
			caseDesc: "root without content",
			entry: V001Entry{
				TufObj: models.TUFV001Schema{
					Root:     &models.TUFV001SchemaRoot{},
					Metadata: &models.TUFV001SchemaMetadata{},
				},
			},
			expectUnmarshalSuccess: false,
			expectVerifierSuccess:  false,
		},
		{
			caseDesc: "root without manifest",
			entry: V001Entry{
				TufObj: models.TUFV001Schema{
					Root: &models.TUFV001SchemaRoot{
						Content: keyContent,
					},
					Metadata: &models.TUFV001SchemaMetadata{},
				},
			},
			expectUnmarshalSuccess: false,
			expectVerifierSuccess:  true,
		},
		{
			caseDesc: "root with invalid manifest & valid metadata",
			entry: V001Entry{
				TufObj: models.TUFV001Schema{
					Root: &models.TUFV001SchemaRoot{
						Content: anyContent,
					},
					Metadata: &models.TUFV001SchemaMetadata{
						Content: dataContent,
					},
				},
			},
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
			expectVerifierSuccess:     false,
		},
		{
			caseDesc: "root with manifest & content",
			entry: V001Entry{
				TufObj: models.TUFV001Schema{
					Root: &models.TUFV001SchemaRoot{
						Content: keyContent,
					},
					Metadata: &models.TUFV001SchemaMetadata{
						Content: dataContent,
					},
				},
			},
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
			expectVerifierSuccess:     true,
		},
		{
			caseDesc: "root with manifest & content base64-encoded",
			entry: V001Entry{
				TufObj: models.TUFV001Schema{
					Root: &models.TUFV001SchemaRoot{
						Content: base64.StdEncoding.EncodeToString(keyBytes),
					},
					Metadata: &models.TUFV001SchemaMetadata{
						Content: base64.StdEncoding.EncodeToString(dataBytes),
					},
				},
			},
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
			expectVerifierSuccess:     true,
		},
		{
			caseDesc: "root with invalid key content & with manifest with content",
			entry: V001Entry{
				TufObj: models.TUFV001Schema{
					Root: &models.TUFV001SchemaRoot{
						Content: dataContent,
					},
					Metadata: &models.TUFV001SchemaMetadata{
						Content: dataContent,
					},
				},
			},
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
			expectVerifierSuccess:     false,
		},
		{
			caseDesc: "public key with key content & with invalid data with content",
			entry: V001Entry{
				TufObj: models.TUFV001Schema{
					Root: &models.TUFV001SchemaRoot{
						Content: keyContent,
					},
					Metadata: &models.TUFV001SchemaMetadata{
						Content: anyContent,
					},
				},
			},
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
			expectVerifierSuccess:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.caseDesc, func(t *testing.T) {
			if err := tc.entry.Validate(); (err == nil) != tc.expectUnmarshalSuccess {
				t.Errorf("unexpected result in '%v': %v", tc.caseDesc, err)
			}
			// No need to continue here if we failed at unmarshal
			if !tc.expectUnmarshalSuccess {
				return
			}

			v := &V001Entry{}
			r := models.TUF{
				APIVersion: swag.String(tc.entry.APIVersion()),
				Spec:       tc.entry.TufObj,
			}

			unmarshalAndValidate := func() error {
				if err := v.Unmarshal(&r); err != nil {
					return err
				}
				return v.Validate()
			}
			if err := unmarshalAndValidate(); (err == nil) != tc.expectUnmarshalSuccess {
				t.Errorf("unexpected result in '%v': %v", tc.caseDesc, err)
			}

			if tc.expectUnmarshalSuccess {
				if ok, err := v.Insertable(); !ok || err != nil {
					t.Errorf("unexpected error calling Insertable on valid proposed entry: %v", err)
				}
			}

			b, err := v.Canonicalize(context.TODO())
			if (err == nil) != tc.expectCanonicalizeSuccess {
				t.Errorf("unexpected result from Canonicalize for '%v': %v", tc.caseDesc, err)
			} else if err != nil {
				if _, ok := err.(types.ValidationError); !ok {
					t.Errorf("canonicalize returned an unexpected error that isn't of type types.ValidationError: %v", err)
				}
			}

			if b != nil {
				pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
				if err != nil {
					t.Errorf("unexpected err from Unmarshalling canonicalized entry for '%v': %v", tc.caseDesc, err)
				}
				ei, err := types.UnmarshalEntry(pe)
				if err != nil {
					t.Errorf("unexpected err from type-specific unmarshalling for '%v': %v", tc.caseDesc, err)
				}
				// Insertable on canonicalized content is variable so we skip testing it here
				hash, err := ei.ArtifactHash()
				if err != nil {
					t.Errorf("unexpected failure with ArtifactHash: %v", err)
				} else if hash != "sha256:c170ae288c93f56031639bac1ad085fc47918346f733b3d76b07a8124ebd24f9" {
					t.Errorf("unexpected match with ArtifactHash: %s", hash)
				}
			}

			verifiers, err := v.Verifiers()
			if tc.expectVerifierSuccess {
				if err != nil {
					t.Errorf("%v: unexpected error, got %v", tc.caseDesc, err)
				} else {
					pub, _ := verifiers[0].CanonicalValue()
					rootBytes := new(bytes.Buffer)
					if err := json.Compact(rootBytes, keyBytes); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(pub, rootBytes.Bytes()) {
						t.Errorf("%v: verifier and public keys do not match: %v, %v", tc.caseDesc, string(pub), rootBytes)
					}
				}
			} else {
				if err == nil {
					s, _ := verifiers[0].CanonicalValue()
					t.Errorf("%v: expected error for %v, got %v", tc.caseDesc, string(s), err)
				}
			}
		})
	}
}

func TestInsertable(t *testing.T) {
	type TestCase struct {
		caseDesc      string
		entry         V001Entry
		expectSuccess bool
	}

	testCases := []TestCase{
		{
			caseDesc: "valid entry",
			entry: V001Entry{
				TufObj: models.TUFV001Schema{
					Metadata: &models.TUFV001SchemaMetadata{
						Content: struct{}{},
					},
					Root: &models.TUFV001SchemaRoot{
						Content: struct{}{},
					},
				},
			},
			expectSuccess: true,
		},
		{
			caseDesc: "missing root content",
			entry: V001Entry{
				TufObj: models.TUFV001Schema{
					Metadata: &models.TUFV001SchemaMetadata{
						Content: struct{}{},
					},
					Root: &models.TUFV001SchemaRoot{
						//Content: struct{}{},
					},
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing root obj",
			entry: V001Entry{
				TufObj: models.TUFV001Schema{
					Metadata: &models.TUFV001SchemaMetadata{
						Content: struct{}{},
					},
					/*
						Root: &models.TUFV001SchemaRoot{
							Content: struct{}{},
						},
					*/
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing metadata content",
			entry: V001Entry{
				TufObj: models.TUFV001Schema{
					Metadata: &models.TUFV001SchemaMetadata{
						//Content: struct{}{},
					},
					Root: &models.TUFV001SchemaRoot{
						Content: struct{}{},
					},
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing metadata content",
			entry: V001Entry{
				TufObj: models.TUFV001Schema{
					/*
						Metadata: &models.TUFV001SchemaMetadata{
							Content: struct{}{},
						},
					*/
					Root: &models.TUFV001SchemaRoot{
						Content: struct{}{},
					},
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc:      "empty obj",
			entry:         V001Entry{},
			expectSuccess: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.caseDesc, func(t *testing.T) {
			if ok, err := tc.entry.Insertable(); ok != tc.expectSuccess {
				t.Errorf("unexpected result calling Insertable: %v", err)
			}
		})
	}
}
