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
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"

	"go.uber.org/goleak"
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

	keyBytes, _ := ioutil.ReadFile("../../../../tests/test_root.json")
	dataBytes, _ := ioutil.ReadFile("../../../../tests/test_timestamp.json")

	testServer := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			file := &keyBytes
			var err error

			switch r.URL.Path {
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
			caseDesc: "root without url or content",
			entry: V001Entry{
				TufObj: models.TufV001Schema{
					Root: &models.TufManifestV001Schema{},
				},
			},
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "root without manifest",
			entry: V001Entry{
				TufObj: models.TufV001Schema{
					Root: &models.TufManifestV001Schema{
						Signed: &models.TufManifestV001SchemaSigned{
							URL: strfmt.URI(testServer.URL + "/key"),
						},
					},
				},
			},
			hasExtEntities:         true,
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "root with empty manifest",
			entry: V001Entry{
				TufObj: models.TufV001Schema{
					Root: &models.TufManifestV001Schema{
						Signed: &models.TufManifestV001SchemaSigned{
							URL: strfmt.URI(testServer.URL + "/key"),
						},
					},
					Manifest: &models.TufManifestV001Schema{},
				},
			},
			hasExtEntities:         true,
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "root with manifest & url",
			entry: V001Entry{
				TufObj: models.TufV001Schema{
					Root: &models.TufManifestV001Schema{
						Signed: &models.TufManifestV001SchemaSigned{
							URL: strfmt.URI(testServer.URL + "/key"),
						},
					},
					Manifest: &models.TufManifestV001Schema{
						Signed: &models.TufManifestV001SchemaSigned{
							URL: strfmt.URI(testServer.URL + "/data"),
						},
					},
				},
			},
			hasExtEntities:            true,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
		},
		{
			caseDesc: "root with manifest & url with 404 error on root",
			entry: V001Entry{
				TufObj: models.TufV001Schema{
					Root: &models.TufManifestV001Schema{
						Signed: &models.TufManifestV001SchemaSigned{
							URL: strfmt.URI(testServer.URL + "/404"),
						},
					},
					Manifest: &models.TufManifestV001Schema{
						Signed: &models.TufManifestV001SchemaSigned{
							URL: strfmt.URI(testServer.URL + "/data"),
						},
					},
				},
			},
			hasExtEntities:            true,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
		},
		{
			caseDesc: "root with data & url with 404 error on manifest",
			entry: V001Entry{
				TufObj: models.TufV001Schema{
					Root: &models.TufManifestV001Schema{
						Signed: &models.TufManifestV001SchemaSigned{
							URL: strfmt.URI(testServer.URL + "/key"),
						},
					},
					Manifest: &models.TufManifestV001Schema{
						Signed: &models.TufManifestV001SchemaSigned{
							URL: strfmt.URI(testServer.URL + "/404"),
						},
					},
				},
			},
			hasExtEntities:            true,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
		},
		{
			caseDesc: "root with invalid key content & with manifest with content",
			entry: V001Entry{
				TufObj: models.TufV001Schema{
					Root: &models.TufManifestV001Schema{
						Signed: &models.TufManifestV001SchemaSigned{
							Content: strfmt.Base64(dataBytes),
						},
					},
					Manifest: &models.TufManifestV001Schema{
						Signed: &models.TufManifestV001SchemaSigned{
							Content: strfmt.Base64(dataBytes),
						},
					},
				},
			},
			hasExtEntities:            false,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
		},
		{
			caseDesc: "root with data & url and valid manifest",
			entry: V001Entry{
				TufObj: models.TufV001Schema{
					Root: &models.TufManifestV001Schema{
						Signed: &models.TufManifestV001SchemaSigned{
							URL: strfmt.URI(testServer.URL + "/key"),
						},
					},
					Manifest: &models.TufManifestV001Schema{
						Signed: &models.TufManifestV001SchemaSigned{
							URL: strfmt.URI(testServer.URL + "/data"),
						},
					},
				},
			},
			hasExtEntities:            true,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
		},
		{
			caseDesc: "public key with key content & with data with content",
			entry: V001Entry{
				TufObj: models.TufV001Schema{
					Root: &models.TufManifestV001Schema{
						Signed: &models.TufManifestV001SchemaSigned{
							Content: strfmt.Base64(keyBytes),
						},
					},
					Manifest: &models.TufManifestV001Schema{
						Signed: &models.TufManifestV001SchemaSigned{
							Content: strfmt.Base64(dataBytes),
						},
					},
				},
			},
			hasExtEntities:            false,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
		},
		{
			caseDesc: "valid obj with extradata",
			entry: V001Entry{
				TufObj: models.TufV001Schema{
					Root: &models.TufManifestV001Schema{
						Signed: &models.TufManifestV001SchemaSigned{
							Content: strfmt.Base64(keyBytes),
						},
					},
					Manifest: &models.TufManifestV001Schema{
						Signed: &models.TufManifestV001SchemaSigned{
							Content: strfmt.Base64(dataBytes),
						},
					},
					ExtraData: []byte("{\"something\": \"here\""),
				},
			},
			hasExtEntities:            false,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
		},
	}

	for _, tc := range testCases {
		if err := tc.entry.Validate(); (err == nil) != tc.expectUnmarshalSuccess {
			t.Errorf("unexpected result in '%v': %v", tc.caseDesc, err)
		}

		v := &V001Entry{}
		r := models.Tuf{
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
