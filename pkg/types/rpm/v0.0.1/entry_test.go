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

package rpm

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
	}

	keyBytes, _ := os.ReadFile("../../../../tests/test_rpm_public_key.key")
	dataBytes, _ := os.ReadFile("../../../../tests/test.rpm")

	testCases := []TestCase{
		{
			caseDesc:               "empty obj",
			entry:                  V001Entry{},
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "public key without content",
			entry: V001Entry{
				RPMModel: models.RpmV001Schema{
					PublicKey: &models.RpmV001SchemaPublicKey{},
				},
			},
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "public key without package",
			entry: V001Entry{
				RPMModel: models.RpmV001Schema{
					PublicKey: &models.RpmV001SchemaPublicKey{
						Content: (*strfmt.Base64)(&keyBytes),
					},
				},
			},
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "public key with empty package",
			entry: V001Entry{
				RPMModel: models.RpmV001Schema{
					PublicKey: &models.RpmV001SchemaPublicKey{
						Content: (*strfmt.Base64)(&keyBytes),
					},
					Package: &models.RpmV001SchemaPackage{},
				},
			},
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "public key with invalid key content & with data with content",
			entry: V001Entry{
				RPMModel: models.RpmV001Schema{
					PublicKey: &models.RpmV001SchemaPublicKey{
						Content: (*strfmt.Base64)(&dataBytes),
					},
					Package: &models.RpmV001SchemaPackage{
						Content: strfmt.Base64(dataBytes),
					},
				},
			},
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
		},
		{
			caseDesc: "public key with key content & with data with content",
			entry: V001Entry{
				RPMModel: models.RpmV001Schema{
					PublicKey: &models.RpmV001SchemaPublicKey{
						Content: (*strfmt.Base64)(&keyBytes),
					},
					Package: &models.RpmV001SchemaPackage{
						Content: strfmt.Base64(dataBytes),
					},
				},
			},
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
		},
		{
			caseDesc: "public key with key content & with invalid data with content",
			entry: V001Entry{
				RPMModel: models.RpmV001Schema{
					PublicKey: &models.RpmV001SchemaPublicKey{
						Content: (*strfmt.Base64)(&keyBytes),
					},
					Package: &models.RpmV001SchemaPackage{
						Content: strfmt.Base64(keyBytes),
					},
				},
			},
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
		},
	}

	for _, tc := range testCases {
		if err := tc.entry.validate(); (err == nil) != tc.expectUnmarshalSuccess {
			t.Errorf("unexpected result in '%v': %v", tc.caseDesc, err)
		}

		v := &V001Entry{}
		r := models.Rpm{
			APIVersion: swag.String(tc.entry.APIVersion()),
			Spec:       tc.entry.RPMModel,
		}

		unmarshalAndValidate := func() error {
			if err := v.Unmarshal(&r); err != nil {
				return err
			}
			return v.validate()
		}
		if err := unmarshalAndValidate(); (err == nil) != tc.expectUnmarshalSuccess {
			t.Errorf("unexpected result in '%v': %v", tc.caseDesc, err)
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
	}
}
