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

package alpine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

	keyBytes, _ := os.ReadFile("../tests/test_alpine.pub")
	dataBytes, _ := os.ReadFile("../tests/test_alpine.apk")

	testCases := []TestCase{
		{
			caseDesc:                "empty obj",
			entry:                   V001Entry{},
			expectUnmarshalSuccess:  false,
			expectedVerifierSuccess: false,
		},
		{
			caseDesc: "public key without content",
			entry: V001Entry{
				AlpineModel: models.AlpineV001Schema{
					PublicKey: &models.AlpineV001SchemaPublicKey{},
				},
			},
			expectUnmarshalSuccess:  false,
			expectedVerifierSuccess: false,
		},
		{
			caseDesc: "public key without package",
			entry: V001Entry{
				AlpineModel: models.AlpineV001Schema{
					PublicKey: &models.AlpineV001SchemaPublicKey{
						Content: (*strfmt.Base64)(&keyBytes),
					},
				},
			},
			expectUnmarshalSuccess:  false,
			expectedVerifierSuccess: true,
		},
		{
			caseDesc: "public key with empty package",
			entry: V001Entry{
				AlpineModel: models.AlpineV001Schema{
					PublicKey: &models.AlpineV001SchemaPublicKey{
						Content: (*strfmt.Base64)(&keyBytes),
					},
					Package: &models.AlpineV001SchemaPackage{},
				},
			},
			expectUnmarshalSuccess:  false,
			expectedVerifierSuccess: true,
		},
		{
			caseDesc: "public key with invalid key content & with data with content",
			entry: V001Entry{
				AlpineModel: models.AlpineV001Schema{
					PublicKey: &models.AlpineV001SchemaPublicKey{
						Content: (*strfmt.Base64)(&dataBytes),
					},
					Package: &models.AlpineV001SchemaPackage{
						Content: strfmt.Base64(dataBytes),
					},
				},
			},
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
			expectedVerifierSuccess:   false,
		},
		{
			caseDesc: "public key with key content & with data with content",
			entry: V001Entry{
				AlpineModel: models.AlpineV001Schema{
					PublicKey: &models.AlpineV001SchemaPublicKey{
						Content: (*strfmt.Base64)(&keyBytes),
					},
					Package: &models.AlpineV001SchemaPackage{
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
		if err := tc.entry.validate(); (err == nil) != tc.expectUnmarshalSuccess {
			t.Errorf("unexpected result in '%v': %v", tc.caseDesc, err)
		}

		v := &V001Entry{}
		r := models.Alpine{
			APIVersion: swag.String(tc.entry.APIVersion()),
			Spec:       tc.entry.AlpineModel,
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

		if tc.expectUnmarshalSuccess {
			if ok, err := v.Insertable(); !ok || err != nil {
				t.Errorf("unexpected result in calling Insertable on valid proposed entry: %v", err)
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
			if ok, err := ei.Insertable(); ok || err == nil {
				t.Errorf("unexpected success calling Insertable on entry created from canonicalized content")
			}
			hash, err := ei.ArtifactHash()
			expectedHash := sha256.Sum256(dataBytes)
			if err != nil {
				t.Errorf("unexpected failure with ArtifactHash: %v", err)
			} else if hash != "sha256:"+hex.EncodeToString(expectedHash[:]) {
				t.Errorf("unexpected match with ArtifactHash: %s", hash)
			}
		}

		verifiers, err := v.Verifiers()
		if tc.expectedVerifierSuccess {
			if err != nil {
				t.Errorf("%v: unexpected error, got %v", tc.caseDesc, err)
			} else {
				pub, _ := verifiers[0].CanonicalValue()
				if !reflect.DeepEqual(pub, keyBytes) {
					t.Errorf("%v: verifier and public keys do not match: %v, %v", tc.caseDesc, string(pub), string(keyBytes))
				}
			}
		} else {
			if err == nil {
				s, _ := verifiers[0].CanonicalValue()
				t.Errorf("%v: expected error for %v, got %v", tc.caseDesc, string(s), err)
			}
		}
	}
}

func TestInsertable(t *testing.T) {
	type TestCase struct {
		caseDesc      string
		entry         V001Entry
		expectSuccess bool
	}

	pub := strfmt.Base64([]byte("pub"))

	testCases := []TestCase{
		{
			caseDesc: "valid entry",
			entry: V001Entry{
				AlpineModel: models.AlpineV001Schema{
					Package: &models.AlpineV001SchemaPackage{
						Content: strfmt.Base64("package"),
					},
					PublicKey: &models.AlpineV001SchemaPublicKey{
						Content: &pub,
					},
				},
			},
			expectSuccess: true,
		},
		{
			caseDesc: "missing key content",
			entry: V001Entry{
				AlpineModel: models.AlpineV001Schema{
					Package: &models.AlpineV001SchemaPackage{
						Content: strfmt.Base64("package"),
					},
					PublicKey: &models.AlpineV001SchemaPublicKey{
						//Content: &pub,
					},
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing public key",
			entry: V001Entry{
				AlpineModel: models.AlpineV001Schema{
					Package: &models.AlpineV001SchemaPackage{
						Content: strfmt.Base64("package"),
					},
					/*
						PublicKey: &models.AlpineV001SchemaPublicKey{
							Content: &pub,
						},
					*/
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing package content",
			entry: V001Entry{
				AlpineModel: models.AlpineV001Schema{
					Package: &models.AlpineV001SchemaPackage{
						//Content: strfmt.Base64("package"),
					},
					PublicKey: &models.AlpineV001SchemaPublicKey{
						Content: &pub,
					},
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing package",
			entry: V001Entry{
				AlpineModel: models.AlpineV001Schema{
					/*
						Package: &models.AlpineV001SchemaPackage{
							Content: strfmt.Base64("package"),
						},
					*/
					PublicKey: &models.AlpineV001SchemaPublicKey{
						Content: &pub,
					},
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "empty model",
			entry: V001Entry{
				AlpineModel: models.AlpineV001Schema{
					/*
						Package: &models.AlpineV001SchemaPackage{
							Content: strfmt.Base64("package"),
						},
						PublicKey: &models.AlpineV001SchemaPublicKey{
							Content: &pub,
						},
					*/
				},
			},
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
