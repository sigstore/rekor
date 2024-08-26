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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"go.uber.org/goleak"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/rekord"
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

		if ok, err := v.Insertable(); !ok || err != nil {
			t.Errorf("unexpected error calling Insertable on valid proposed entry: %v", err)
		}

		b, err := v.Canonicalize(context.TODO())
		if (err == nil) != tc.expectCanonicalizeSuccess {
			t.Errorf("unexpected result from Canonicalize for '%v': %v", tc.caseDesc, err)
		} else if err != nil {
			var validationErr *types.InputValidationError
			if !errors.As(err, &validationErr) {
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
	}
}

func TestUnspecifiedPKIFormat(t *testing.T) {
	props := types.ArtifactProperties{
		ArtifactBytes:  []byte("something"),
		SignatureBytes: []byte("signature"),
		PublicKeyBytes: [][]byte{[]byte("public_key")},
		// PKIFormat is deliberately unspecified
	}
	rek := rekord.New()
	if _, err := rek.CreateProposedEntry(context.Background(), APIVERSION, props); err == nil {
		t.Errorf("no signature, public key or format should not create a valid entry")
	}

	props.PKIFormat = "invalid_format"
	if _, err := rek.CreateProposedEntry(context.Background(), APIVERSION, props); err == nil {
		t.Errorf("invalid pki format should not create a valid entry")
	}
}

func TestInsertable(t *testing.T) {
	type TestCase struct {
		caseDesc      string
		entry         V001Entry
		expectSuccess bool
	}

	sig := strfmt.Base64([]byte("sig"))
	pub := strfmt.Base64([]byte("pub"))
	testCases := []TestCase{
		{
			caseDesc: "valid entry",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Data: &models.RekordV001SchemaData{
						Content: strfmt.Base64([]byte("content")),
					},
					Signature: &models.RekordV001SchemaSignature{
						Content: &sig,
						Format:  swag.String("format"),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							Content: &pub,
						},
					},
				},
			},
			expectSuccess: true,
		},
		{
			caseDesc: "missing public key content",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Data: &models.RekordV001SchemaData{
						Content: strfmt.Base64([]byte("content")),
					},
					Signature: &models.RekordV001SchemaSignature{
						Content:   &sig,
						Format:    swag.String("format"),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							//Content: &pub,
						},
					},
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing public key obj",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Data: &models.RekordV001SchemaData{
						Content: strfmt.Base64([]byte("content")),
					},
					Signature: &models.RekordV001SchemaSignature{
						Content: &sig,
						Format:  swag.String("format"),
						/*
							PublicKey: &models.RekordV001SchemaSignaturePublicKey{
								Content: &pub,
							},
						*/
					},
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing format string",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Data: &models.RekordV001SchemaData{
						Content: strfmt.Base64([]byte("content")),
					},
					Signature: &models.RekordV001SchemaSignature{
						Content: &sig,
						//Format:  swag.String("format"),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							Content: &pub,
						},
					},
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing signature content",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Data: &models.RekordV001SchemaData{
						Content: strfmt.Base64([]byte("content")),
					},
					Signature: &models.RekordV001SchemaSignature{
						//Content: &sig,
						Format: swag.String("format"),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							Content: &pub,
						},
					},
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing signature obj",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Data: &models.RekordV001SchemaData{
						Content: strfmt.Base64([]byte("content")),
					},
					/*
						Signature: &models.RekordV001SchemaSignature{
							Content: &sig,
							Format:  swag.String("format"),
							PublicKey: &models.RekordV001SchemaSignaturePublicKey{
								Content: &pub,
							},
						},
					*/
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing data content",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Data: &models.RekordV001SchemaData{
						//Content: strfmt.Base64([]byte("content")),
					},
					Signature: &models.RekordV001SchemaSignature{
						Content: &sig,
						Format:  swag.String("format"),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							Content: &pub,
						},
					},
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing data obj",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					/*
						Data: &models.RekordV001SchemaData{
							Content: strfmt.Base64([]byte("content")),
						},
					*/
					Signature: &models.RekordV001SchemaSignature{
						Content: &sig,
						Format:  swag.String("format"),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							Content: &pub,
						},
					},
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "empty obj",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					/*
						Data: &models.RekordV001SchemaData{
							Content: strfmt.Base64([]byte("content")),
						},
						Signature: &models.RekordV001SchemaSignature{
							Content: &sig,
							Format:  swag.String("format"),
							PublicKey: &models.RekordV001SchemaSignaturePublicKey{
								Content: &pub,
							},
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
