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

package hashed_rekord

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
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
		hasExtEntities            bool
		expectUnmarshalSuccess    bool
		expectCanonicalizeSuccess bool
	}

	sigBytes, _ := ioutil.ReadFile("../../../../tests/test_file.sig")
	keyBytes, _ := ioutil.ReadFile("../../../../tests/test_public_key.key")
	dataBytes, _ := ioutil.ReadFile("../../../../tests/test_file.txt")

	h := sha256.Sum256(dataBytes)
	dataSHA := hex.EncodeToString(h[:])

	testServer := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			file := &sigBytes
			var err error

			switch r.URL.Path {
			case "/signature":
				file = &sigBytes
			case "/key":
				file = &keyBytes
			case "/data":
				file = &dataBytes
			default:
				err = errors.New("unknown URL")
			}
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(*file)
		}))
	defer testServer.Close()

	testCases := []TestCase{
		{
			caseDesc:               "empty obj",
			entry:                  V001Entry{},
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "signature without url or content",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: "pgp",
					},
				},
			},
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "signature without public key",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: "pgp",
						URL:    strfmt.URI(testServer.URL + "/signature"),
					},
				},
			},
			hasExtEntities:         true,
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "signature with empty public key",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format:    "pgp",
						URL:       strfmt.URI(testServer.URL + "/signature"),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{},
					},
				},
			},
			hasExtEntities:         true,
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "signature without data",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: "pgp",
						URL:    strfmt.URI(testServer.URL + "/signature"),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							URL: strfmt.URI(testServer.URL + "/key"),
						},
					},
				},
			},
			hasExtEntities:         true,
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "signature with empty data",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: "pgp",
						URL:    strfmt.URI(testServer.URL + "/signature"),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							URL: strfmt.URI(testServer.URL + "/key"),
						},
					},
					Data: &models.RekordV001SchemaData{},
				},
			},
			hasExtEntities:         true,
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "signature with data & url but no hash",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: "pgp",
						URL:    strfmt.URI(testServer.URL + "/signature"),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							URL: strfmt.URI(testServer.URL + "/key"),
						},
					},
					Data: &models.RekordV001SchemaData{
						URL: strfmt.URI(testServer.URL + "/data"),
					},
				},
			},
			hasExtEntities:            true,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
		},
		{
			caseDesc: "signature with data & url and empty hash",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: "pgp",
						URL:    strfmt.URI(testServer.URL + "/signature"),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							URL: strfmt.URI(testServer.URL + "/key"),
						},
					},
					Data: &models.RekordV001SchemaData{
						Hash: &models.RekordV001SchemaDataHash{},
						URL:  strfmt.URI(testServer.URL + "/data"),
					},
				},
			},
			hasExtEntities:         true,
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "signature with data & url and hash missing value",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: "pgp",
						URL:    strfmt.URI(testServer.URL + "/signature"),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							URL: strfmt.URI(testServer.URL + "/key"),
						},
					},
					Data: &models.RekordV001SchemaData{
						Hash: &models.RekordV001SchemaDataHash{
							Algorithm: swag.String(models.RekordV001SchemaDataHashAlgorithmSha256),
						},
						URL: strfmt.URI(testServer.URL + "/data"),
					},
				},
			},
			hasExtEntities:         true,
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "signature with data & url with 404 error on signature",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: "pgp",
						URL:    strfmt.URI(testServer.URL + "/404"),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							URL: strfmt.URI(testServer.URL + "/key"),
						},
					},
					Data: &models.RekordV001SchemaData{
						Hash: &models.RekordV001SchemaDataHash{
							Algorithm: swag.String(models.RekordV001SchemaDataHashAlgorithmSha256),
							Value:     swag.String(dataSHA),
						},
						URL: strfmt.URI(testServer.URL + "/data"),
					},
				},
			},
			hasExtEntities:            true,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
		},
		{
			caseDesc: "signature with data & url with 404 error on key",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: "pgp",
						URL:    strfmt.URI(testServer.URL + "/signature"),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							URL: strfmt.URI(testServer.URL + "/404"),
						},
					},
					Data: &models.RekordV001SchemaData{
						Hash: &models.RekordV001SchemaDataHash{
							Algorithm: swag.String(models.RekordV001SchemaDataHashAlgorithmSha256),
							Value:     swag.String(dataSHA),
						},
						URL: strfmt.URI(testServer.URL + "/data"),
					},
				},
			},
			hasExtEntities:            true,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
		},
		{
			caseDesc: "signature with data & url with 404 error on data",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: "pgp",
						URL:    strfmt.URI(testServer.URL + "/signature"),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							URL: strfmt.URI(testServer.URL + "/key"),
						},
					},
					Data: &models.RekordV001SchemaData{
						Hash: &models.RekordV001SchemaDataHash{
							Algorithm: swag.String(models.RekordV001SchemaDataHashAlgorithmSha256),
							Value:     swag.String(dataSHA),
						},
						URL: strfmt.URI(testServer.URL + "/404"),
					},
				},
			},
			hasExtEntities:            true,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
		},
		{
			caseDesc: "signature with invalid sig content, key content & with data with content",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format:  "pgp",
						Content: strfmt.Base64(dataBytes),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							Content: strfmt.Base64(keyBytes),
						},
					},
					Data: &models.RekordV001SchemaData{
						Content: strfmt.Base64(dataBytes),
					},
				},
			},
			hasExtEntities:            false,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
		},
		{
			caseDesc: "signature with sig content, invalid key content & with data with content",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format:  "pgp",
						Content: strfmt.Base64(sigBytes),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							Content: strfmt.Base64(dataBytes),
						},
					},
					Data: &models.RekordV001SchemaData{
						Content: strfmt.Base64(dataBytes),
					},
				},
			},
			hasExtEntities:            false,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
		},
		{
			caseDesc: "signature with sig content, key content & with data with content",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format:  "pgp",
						Content: strfmt.Base64(sigBytes),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							Content: strfmt.Base64(dataBytes),
						},
					},
					Data: &models.RekordV001SchemaData{
						Content: strfmt.Base64(dataBytes),
					},
				},
			},
			hasExtEntities:            false,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
		},
		{
			caseDesc: "signature with data & url and incorrect hash value",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: "pgp",
						URL:    strfmt.URI(testServer.URL + "/signature"),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							URL: strfmt.URI(testServer.URL + "/key"),
						},
					},
					Data: &models.RekordV001SchemaData{
						Hash: &models.RekordV001SchemaDataHash{
							Algorithm: swag.String(models.RekordV001SchemaDataHashAlgorithmSha256),
							Value:     swag.String("3030303030303030303030303030303030303030303030303030303030303030"),
						},
						URL: strfmt.URI(testServer.URL + "/data"),
					},
				},
			},
			hasExtEntities:            true,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
		},
		{
			caseDesc: "signature with data & url and complete hash value",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: "pgp",
						URL:    strfmt.URI(testServer.URL + "/signature"),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							URL: strfmt.URI(testServer.URL + "/key"),
						},
					},
					Data: &models.RekordV001SchemaData{
						Hash: &models.RekordV001SchemaDataHash{
							Algorithm: swag.String(models.RekordV001SchemaDataHashAlgorithmSha256),
							Value:     swag.String(dataSHA),
						},
						URL: strfmt.URI(testServer.URL + "/data"),
					},
				},
			},
			hasExtEntities:            true,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
		},
		{
			caseDesc: "signature with sig content, url key & with data with url and complete hash value",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format:  "pgp",
						Content: strfmt.Base64(sigBytes),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							URL: strfmt.URI(testServer.URL + "/key"),
						},
					},
					Data: &models.RekordV001SchemaData{
						Hash: &models.RekordV001SchemaDataHash{
							Algorithm: swag.String(models.RekordV001SchemaDataHashAlgorithmSha256),
							Value:     swag.String(dataSHA),
						},
						URL: strfmt.URI(testServer.URL + "/data"),
					},
				},
			},
			hasExtEntities:            true,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
		},
		{
			caseDesc: "signature with sig url, key content & with data with url and complete hash value",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: "pgp",
						URL:    strfmt.URI(testServer.URL + "/signature"),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							Content: strfmt.Base64(keyBytes),
						},
					},
					Data: &models.RekordV001SchemaData{
						Hash: &models.RekordV001SchemaDataHash{
							Algorithm: swag.String(models.RekordV001SchemaDataHashAlgorithmSha256),
							Value:     swag.String(dataSHA),
						},
						URL: strfmt.URI(testServer.URL + "/data"),
					},
				},
			},
			hasExtEntities:            true,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
		},
		{
			caseDesc: "signature with sig content, key content & with data with url and complete hash value",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format:  "pgp",
						Content: strfmt.Base64(sigBytes),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							Content: strfmt.Base64(keyBytes),
						},
					},
					Data: &models.RekordV001SchemaData{
						Hash: &models.RekordV001SchemaDataHash{
							Algorithm: swag.String(models.RekordV001SchemaDataHashAlgorithmSha256),
							Value:     swag.String(dataSHA),
						},
						URL: strfmt.URI(testServer.URL + "/data"),
					},
				},
			},
			hasExtEntities:            true,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
		},
		{
			caseDesc: "signature with sig content, key content & with data with content",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format:  "pgp",
						Content: strfmt.Base64(sigBytes),
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							Content: strfmt.Base64(keyBytes),
						},
					},
					Data: &models.RekordV001SchemaData{
						Content: strfmt.Base64(dataBytes),
					},
				},
			},
			hasExtEntities:            false,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
		},
	}

	for _, tc := range testCases {
		if err := tc.entry.validate(); (err == nil) != tc.expectUnmarshalSuccess {
			t.Errorf("unexpected result in '%v': %v", tc.caseDesc, err)
		}

		v := &V001Entry{}
		r := models.Rekord{
			APIVersion: swag.String(tc.entry.APIVersion()),
			Spec:       tc.entry.RekordObj,
		}

		unmarshalAndValidate := func() error {
			if err := v.Unmarshal(&r); err != nil {
				return err
			}
			if err := v.validate(); err != nil {
				return err
			}
			return nil
		}

		if err := unmarshalAndValidate(); (err == nil) != tc.expectUnmarshalSuccess {
			t.Errorf("unexpected result in '%v': %v", tc.caseDesc, err)
		}

		if tc.entry.HasExternalEntities() != tc.hasExtEntities {
			t.Errorf("unexpected result from HasExternalEntities for '%v'", tc.caseDesc)
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
			if _, err := types.NewEntry(pe); err != nil {
				t.Errorf("unexpected err from type-specific unmarshalling for '%v': %v", tc.caseDesc, err)
			}
		}
	}
}
