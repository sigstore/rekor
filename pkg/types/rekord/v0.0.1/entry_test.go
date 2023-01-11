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

package rekord

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"go.uber.org/goleak"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
)

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
	type TestCase struct {
		caseDesc                  string
		entry                     V001Entry
		expectUnmarshalSuccess    bool
		expectCanonicalizeSuccess bool
		expectedVerifierSuccess   bool
	}

	sigBytes, _ := os.ReadFile("../tests/test_file.sig")
	keyBytes, _ := os.ReadFile("../tests/test_public_key.key")
	dataBytes, _ := os.ReadFile("../tests/test_file.txt")

	testCases := []TestCase{
		{
			caseDesc:                "empty obj",
			entry:                   V001Entry{},
			expectUnmarshalSuccess:  false,
			expectedVerifierSuccess: false,
		},
		{
			caseDesc: "signature without url or content",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: swag.String("pgp"),
					},
				},
			},
			expectUnmarshalSuccess:  false,
			expectedVerifierSuccess: false,
		},
		{
			caseDesc: "signature without public key",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format:  swag.String("pgp"),
						Content: (*strfmt.Base64)(&sigBytes),
					},
				},
			},
			expectUnmarshalSuccess:  false,
			expectedVerifierSuccess: false,
		},
		{
			caseDesc: "signature with empty public key",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format:    swag.String("pgp"),
						Content:   (*strfmt.Base64)(&sigBytes),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{},
					},
				},
			},
			expectUnmarshalSuccess:  false,
			expectedVerifierSuccess: false,
		},
		{
			caseDesc: "signature without data",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format:  swag.String("pgp"),
						Content: (*strfmt.Base64)(&sigBytes),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							Content: (*strfmt.Base64)(&keyBytes),
						},
					},
				},
			},
			expectUnmarshalSuccess:  false,
			expectedVerifierSuccess: true,
		},
		{
			caseDesc: "signature with empty data",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format:  swag.String("pgp"),
						Content: (*strfmt.Base64)(&sigBytes),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							Content: (*strfmt.Base64)(&keyBytes),
						},
					},
					Data: &models.RekordV001SchemaData{},
				},
			},
			expectUnmarshalSuccess:  false,
			expectedVerifierSuccess: true,
		},
		{
			caseDesc: "signature with invalid sig content, key content & with data with content",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format:  swag.String("pgp"),
						Content: (*strfmt.Base64)(&dataBytes),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							Content: (*strfmt.Base64)(&keyBytes),
						},
					},
					Data: &models.RekordV001SchemaData{
						Content: strfmt.Base64(dataBytes),
					},
				},
			},
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
			expectedVerifierSuccess:   true,
		},
		{
			caseDesc: "signature with sig content, invalid key content & with data with content",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format:  swag.String("pgp"),
						Content: (*strfmt.Base64)(&sigBytes),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							Content: (*strfmt.Base64)(&dataBytes),
						},
					},
					Data: &models.RekordV001SchemaData{
						Content: strfmt.Base64(dataBytes),
					},
				},
			},
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
			expectedVerifierSuccess:   false,
		},
		{
			caseDesc: "signature with sig content, key content & with data with content",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format:  swag.String("pgp"),
						Content: (*strfmt.Base64)(&sigBytes),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							Content: (*strfmt.Base64)(&keyBytes),
						},
					},
					Data: &models.RekordV001SchemaData{
						Content: strfmt.Base64(keyBytes),
					},
				},
			},
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
			expectedVerifierSuccess:   true,
		},
		{
			caseDesc: "signature with sig content, key content & with data with content",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format:  swag.String("pgp"),
						Content: (*strfmt.Base64)(&sigBytes),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							Content: (*strfmt.Base64)(&keyBytes),
						},
					},
					Data: &models.RekordV001SchemaData{
						Content: strfmt.Base64(dataBytes),
					},
				},
			},
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
			expectedVerifierSuccess:   true,
		},
	}

	for _, tc := range testCases {
		v := &V001Entry{}
		r := models.Rekord{
			APIVersion: swag.String(tc.entry.APIVersion()),
			Spec:       tc.entry.RekordObj,
		}

		if err := v.Unmarshal(&r); (err == nil) != tc.expectUnmarshalSuccess {
			t.Fatalf("unexpected result in '%v': %v", tc.caseDesc, err)
		}
		// No need to continue here if we didn't unmarshal
		if !tc.expectUnmarshalSuccess {
			continue
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
			if _, err := types.UnmarshalEntry(pe); err != nil {
				t.Errorf("unexpected err from type-specific unmarshalling for '%v': %v", tc.caseDesc, err)
			}
		}

		verifier, err := v.Verifier()
		if tc.expectedVerifierSuccess {
			if err != nil {
				t.Errorf("%v: unexpected error, got %v", tc.caseDesc, err)
			} else {
				// TODO: Improve this test once CanonicalValue returns same result as input for PGP keys
				_, err := verifier.CanonicalValue()
				if err != nil {
					t.Errorf("%v: unexpected error getting canonical value, got %v", tc.caseDesc, err)
				}
			}

		} else {
			if err == nil {
				s, _ := verifier.CanonicalValue()
				t.Errorf("%v: expected error for %v, got %v", tc.caseDesc, string(s), err)
			}
		}
	}
}
