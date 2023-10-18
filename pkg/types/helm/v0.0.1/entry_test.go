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

package helm

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

	keyBytes, _ := os.ReadFile("../tests/test_helm_armor.pub")
	provenanceBytes, _ := os.ReadFile("../tests/test-0.1.0.tgz.prov")

	testCases := []TestCase{
		{
			caseDesc:                "empty obj",
			entry:                   V001Entry{},
			expectUnmarshalSuccess:  false,
			expectedVerifierSuccess: false,
		},

		{
			caseDesc: "provenance file without public key",
			entry: V001Entry{
				HelmObj: models.HelmV001Schema{
					Chart: &models.HelmV001SchemaChart{
						Provenance: &models.HelmV001SchemaChartProvenance{
							Content: strfmt.Base64(provenanceBytes),
						},
					},
				},
			},
			expectUnmarshalSuccess:  false,
			expectedVerifierSuccess: false,
		},
		{
			caseDesc: "public key without provenance file",
			entry: V001Entry{
				HelmObj: models.HelmV001Schema{
					PublicKey: &models.HelmV001SchemaPublicKey{
						Content: (*strfmt.Base64)(&keyBytes),
					},
				},
			},
			expectUnmarshalSuccess:  false,
			expectedVerifierSuccess: true,
		},
		{
			caseDesc: "public key with empty provenance file",
			entry: V001Entry{
				HelmObj: models.HelmV001Schema{
					PublicKey: &models.HelmV001SchemaPublicKey{
						Content: (*strfmt.Base64)(&keyBytes),
					},
					Chart: &models.HelmV001SchemaChart{
						Provenance: &models.HelmV001SchemaChartProvenance{},
					},
				},
			},
			expectUnmarshalSuccess:  false,
			expectedVerifierSuccess: true,
		},
		{
			caseDesc: "public key and invalid provenance content",
			entry: V001Entry{
				HelmObj: models.HelmV001Schema{
					PublicKey: &models.HelmV001SchemaPublicKey{
						Content: (*strfmt.Base64)(&keyBytes),
					},
					Chart: &models.HelmV001SchemaChart{
						Provenance: &models.HelmV001SchemaChartProvenance{
							Content: strfmt.Base64(keyBytes),
						},
					},
				},
			},
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
			expectedVerifierSuccess:   true,
		},
		{
			caseDesc: "provenance content with invalid public key",
			entry: V001Entry{
				HelmObj: models.HelmV001Schema{
					PublicKey: &models.HelmV001SchemaPublicKey{
						Content: (*strfmt.Base64)(&provenanceBytes),
					},
					Chart: &models.HelmV001SchemaChart{
						Provenance: &models.HelmV001SchemaChartProvenance{
							Content: strfmt.Base64(provenanceBytes),
						},
					},
				},
			},
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
			expectedVerifierSuccess:   false,
		},
		{
			caseDesc: "provenance content with valid public key",
			entry: V001Entry{
				HelmObj: models.HelmV001Schema{
					PublicKey: &models.HelmV001SchemaPublicKey{
						Content: (*strfmt.Base64)(&keyBytes),
					},
					Chart: &models.HelmV001SchemaChart{
						Provenance: &models.HelmV001SchemaChartProvenance{
							Content: strfmt.Base64(provenanceBytes),
						},
					},
				},
			},
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
			expectedVerifierSuccess:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.caseDesc, func(t *testing.T) {

			if err := tc.entry.validate(); (err == nil) != tc.expectUnmarshalSuccess {
				t.Errorf("unexpected result in '%v': %v", tc.caseDesc, err)
			}

			v := &V001Entry{}
			r := models.Helm{
				APIVersion: swag.String(tc.entry.APIVersion()),
				Spec:       tc.entry.HelmObj,
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
				ok, err := v.Insertable()
				if !ok || err != nil {
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
				if ok, err := ei.Insertable(); ok || err == nil {
					t.Errorf("unexpected success calling Insertable on entry created from canonicalized content")
				}
				hash, err := ei.ArtifactHash()
				if err != nil {
					t.Errorf("unexpected failure with ArtifactHash: %v", err)
				} else if hash != "sha256:6dec7ea21e655d5796c1e214cfb75b73428b2abfa2e66c8f7bc64ff4a7b3b29f" {
					t.Errorf("unexpected match with ArtifactHash: %s", hash)
				}
			}

			verifiers, err := v.Verifiers()
			if tc.expectedVerifierSuccess {
				if err != nil {
					t.Errorf("%v: unexpected error, got %v", tc.caseDesc, err)
				} else {
					// TODO: Improve this test once CanonicalValue returns same result as input for PGP keys
					_, err := verifiers[0].CanonicalValue()
					if err != nil {
						t.Errorf("%v: unexpected error getting canonical value, got %v", tc.caseDesc, err)
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

	pubKey := strfmt.Base64([]byte("pubKey"))

	testCases := []TestCase{
		{
			caseDesc: "valid entry",
			entry: V001Entry{
				HelmObj: models.HelmV001Schema{
					Chart: &models.HelmV001SchemaChart{
						Provenance: &models.HelmV001SchemaChartProvenance{
							Content: strfmt.Base64([]byte("content")),
						},
					},
					PublicKey: &models.HelmV001SchemaPublicKey{
						Content: &pubKey,
					},
				},
			},
			expectSuccess: true,
		},
		{
			caseDesc: "missing key content",
			entry: V001Entry{
				HelmObj: models.HelmV001Schema{
					Chart: &models.HelmV001SchemaChart{
						Provenance: &models.HelmV001SchemaChartProvenance{
							Content: strfmt.Base64([]byte("content")),
						},
					},
					PublicKey: &models.HelmV001SchemaPublicKey{
						//Content: &pubKey,
					},
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing key",
			entry: V001Entry{
				HelmObj: models.HelmV001Schema{
					Chart: &models.HelmV001SchemaChart{
						Provenance: &models.HelmV001SchemaChartProvenance{
							Content: strfmt.Base64([]byte("content")),
						},
					},
					/*
						PublicKey: &models.HelmV001SchemaPublicKey{
							Content: &pubKey,
						},
					*/
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing provenance content",
			entry: V001Entry{
				HelmObj: models.HelmV001Schema{
					Chart: &models.HelmV001SchemaChart{
						Provenance: &models.HelmV001SchemaChartProvenance{
							//Content: strfmt.Base64([]byte("content")),
						},
					},
					PublicKey: &models.HelmV001SchemaPublicKey{
						Content: &pubKey,
					},
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing provenance obj",
			entry: V001Entry{
				HelmObj: models.HelmV001Schema{
					Chart: &models.HelmV001SchemaChart{
						/*
							Provenance: &models.HelmV001SchemaChartProvenance{
								Content: strfmt.Base64([]byte("content")),
							},
						*/
					},
					PublicKey: &models.HelmV001SchemaPublicKey{
						Content: &pubKey,
					},
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing chart obj",
			entry: V001Entry{
				HelmObj: models.HelmV001Schema{
					/*
						Chart: &models.HelmV001SchemaChart{
							Provenance: &models.HelmV001SchemaChartProvenance{
								Content: strfmt.Base64([]byte("content")),
							},
						},
					*/
					PublicKey: &models.HelmV001SchemaPublicKey{
						Content: &pubKey,
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
