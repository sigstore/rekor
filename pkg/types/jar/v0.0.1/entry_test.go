/*
Copyright © 2021 The Sigstore Authors

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

package jar

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/sigstore/rekor/pkg/generated/models"
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

	jarBytes, _ := ioutil.ReadFile("../../../../tests/test.jar")

	h := sha256.New()
	_, _ = h.Write(jarBytes)
	dataSHA := hex.EncodeToString(h.Sum(nil))

	testServer := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			var file *[]byte
			var err error

			switch r.URL.Path {
			case "/data":
				file = &jarBytes
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
			caseDesc: "empty archive",
			entry: V001Entry{
				JARModel: models.JarV001Schema{
					Archive: &models.JarV001SchemaArchive{},
				},
			},
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "archive with url but no hash",
			entry: V001Entry{
				JARModel: models.JarV001Schema{
					Archive: &models.JarV001SchemaArchive{
						URL: strfmt.URI(testServer.URL + "/data"),
					},
				},
			},
			hasExtEntities:         true,
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "archive with url and empty hash",
			entry: V001Entry{
				JARModel: models.JarV001Schema{
					Archive: &models.JarV001SchemaArchive{
						Hash: &models.JarV001SchemaArchiveHash{},
						URL:  strfmt.URI(testServer.URL + "/data"),
					},
				},
			},
			hasExtEntities:         true,
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "archive with url and hash alg but missing value",
			entry: V001Entry{
				JARModel: models.JarV001Schema{
					Archive: &models.JarV001SchemaArchive{
						Hash: &models.JarV001SchemaArchiveHash{
							Algorithm: swag.String(models.JarV001SchemaArchiveHashAlgorithmSha256),
						},
						URL: strfmt.URI(testServer.URL + "/data"),
					},
				},
			},
			hasExtEntities:         true,
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "archive with valid url with matching hash",
			entry: V001Entry{
				JARModel: models.JarV001Schema{
					Archive: &models.JarV001SchemaArchive{
						Hash: &models.JarV001SchemaArchiveHash{
							Algorithm: swag.String(models.JarV001SchemaArchiveHashAlgorithmSha256),
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
			caseDesc: "archive with inline content",
			entry: V001Entry{
				JARModel: models.JarV001Schema{
					Archive: &models.JarV001SchemaArchive{
						Content: strfmt.Base64(jarBytes),
					},
				},
			},
			hasExtEntities:            false,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
		},
		{
			caseDesc: "archive with url and incorrect hash value",
			entry: V001Entry{
				JARModel: models.JarV001Schema{
					Archive: &models.JarV001SchemaArchive{
						Hash: &models.JarV001SchemaArchiveHash{
							Algorithm: swag.String(models.JarV001SchemaArchiveHashAlgorithmSha256),
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
			caseDesc: "valid obj with extradata",
			entry: V001Entry{
				JARModel: models.JarV001Schema{
					Archive: &models.JarV001SchemaArchive{
						Content: strfmt.Base64(jarBytes),
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
		r := models.Jar{
			APIVersion: swag.String(tc.entry.APIVersion()),
			Spec:       tc.entry.JARModel,
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

		if _, err := tc.entry.Canonicalize(context.TODO()); (err == nil) != tc.expectCanonicalizeSuccess {
			t.Errorf("unexpected result from Canonicalize for '%v': %v", tc.caseDesc, err)
		}
	}
}
