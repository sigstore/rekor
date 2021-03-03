/*
Copyright © 2021 Bob Callaway <bcallawa@redhat.com>

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

package rpm

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

	keyBytes, _ := ioutil.ReadFile("../../../../tests/test_rpm_public_key.key")
	dataBytes, _ := ioutil.ReadFile("../../../../tests/test.rpm")

	h := sha256.New()
	_, _ = h.Write(dataBytes)
	dataSHA := hex.EncodeToString(h.Sum(nil))

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
			caseDesc: "public key without url or content",
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
						URL: strfmt.URI(testServer.URL + "/key"),
					},
				},
			},
			hasExtEntities:         true,
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "public key with empty package",
			entry: V001Entry{
				RPMModel: models.RpmV001Schema{
					PublicKey: &models.RpmV001SchemaPublicKey{
						URL: strfmt.URI(testServer.URL + "/key"),
					},
					Package: &models.RpmV001SchemaPackage{},
				},
			},
			hasExtEntities:         true,
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "public key with data & url but no hash",
			entry: V001Entry{
				RPMModel: models.RpmV001Schema{
					PublicKey: &models.RpmV001SchemaPublicKey{
						URL: strfmt.URI(testServer.URL + "/key"),
					},
					Package: &models.RpmV001SchemaPackage{
						URL: strfmt.URI(testServer.URL + "/data"),
					},
				},
			},
			hasExtEntities:            true,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
		},
		{
			caseDesc: "public key with data & url and empty hash",
			entry: V001Entry{
				RPMModel: models.RpmV001Schema{
					PublicKey: &models.RpmV001SchemaPublicKey{
						URL: strfmt.URI(testServer.URL + "/key"),
					},
					Package: &models.RpmV001SchemaPackage{
						Hash: &models.RpmV001SchemaPackageHash{},
						URL:  strfmt.URI(testServer.URL + "/data"),
					},
				},
			},
			hasExtEntities:         true,
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "public key with data & url and hash missing value",
			entry: V001Entry{
				RPMModel: models.RpmV001Schema{
					PublicKey: &models.RpmV001SchemaPublicKey{
						URL: strfmt.URI(testServer.URL + "/key"),
					},
					Package: &models.RpmV001SchemaPackage{
						Hash: &models.RpmV001SchemaPackageHash{
							Algorithm: swag.String(models.RpmV001SchemaPackageHashAlgorithmSha256),
						},
						URL: strfmt.URI(testServer.URL + "/data"),
					},
				},
			},
			hasExtEntities:         true,
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "public key with data & url with 404 error on key",
			entry: V001Entry{
				RPMModel: models.RpmV001Schema{
					PublicKey: &models.RpmV001SchemaPublicKey{
						URL: strfmt.URI(testServer.URL + "/404"),
					},
					Package: &models.RpmV001SchemaPackage{
						Hash: &models.RpmV001SchemaPackageHash{
							Algorithm: swag.String(models.RpmV001SchemaPackageHashAlgorithmSha256),
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
			caseDesc: "public key with data & url with 404 error on data",
			entry: V001Entry{
				RPMModel: models.RpmV001Schema{
					PublicKey: &models.RpmV001SchemaPublicKey{
						URL: strfmt.URI(testServer.URL + "/key"),
					},
					Package: &models.RpmV001SchemaPackage{
						Hash: &models.RpmV001SchemaPackageHash{
							Algorithm: swag.String(models.RpmV001SchemaPackageHashAlgorithmSha256),
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
			caseDesc: "public key with invalid key content & with data with content",
			entry: V001Entry{
				RPMModel: models.RpmV001Schema{
					PublicKey: &models.RpmV001SchemaPublicKey{
						Content: strfmt.Base64(dataBytes),
					},
					Package: &models.RpmV001SchemaPackage{
						Content: strfmt.Base64(dataBytes),
					},
				},
			},
			hasExtEntities:            false,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
		},
		{
			caseDesc: "public key with data & url and incorrect hash value",
			entry: V001Entry{
				RPMModel: models.RpmV001Schema{
					PublicKey: &models.RpmV001SchemaPublicKey{
						URL: strfmt.URI(testServer.URL + "/key"),
					},
					Package: &models.RpmV001SchemaPackage{
						Hash: &models.RpmV001SchemaPackageHash{
							Algorithm: swag.String(models.RpmV001SchemaPackageHashAlgorithmSha256),
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
			caseDesc: "public key with data & url and complete hash value",
			entry: V001Entry{
				RPMModel: models.RpmV001Schema{
					PublicKey: &models.RpmV001SchemaPublicKey{
						URL: strfmt.URI(testServer.URL + "/key"),
					},
					Package: &models.RpmV001SchemaPackage{
						Hash: &models.RpmV001SchemaPackageHash{
							Algorithm: swag.String(models.RpmV001SchemaPackageHashAlgorithmSha256),
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
			caseDesc: "public key with url key & with data with url and complete hash value",
			entry: V001Entry{
				RPMModel: models.RpmV001Schema{
					PublicKey: &models.RpmV001SchemaPublicKey{
						URL: strfmt.URI(testServer.URL + "/key"),
					},
					Package: &models.RpmV001SchemaPackage{
						Hash: &models.RpmV001SchemaPackageHash{
							Algorithm: swag.String(models.RpmV001SchemaPackageHashAlgorithmSha256),
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
			caseDesc: "public key with key content & with data with url and complete hash value",
			entry: V001Entry{
				RPMModel: models.RpmV001Schema{
					PublicKey: &models.RpmV001SchemaPublicKey{
						Content: strfmt.Base64(keyBytes),
					},
					Package: &models.RpmV001SchemaPackage{
						Hash: &models.RpmV001SchemaPackageHash{
							Algorithm: swag.String(models.RpmV001SchemaPackageHashAlgorithmSha256),
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
			caseDesc: "public key with key content & with data with url and complete hash value",
			entry: V001Entry{
				RPMModel: models.RpmV001Schema{
					PublicKey: &models.RpmV001SchemaPublicKey{
						Content: strfmt.Base64(keyBytes),
					},
					Package: &models.RpmV001SchemaPackage{
						Hash: &models.RpmV001SchemaPackageHash{
							Algorithm: swag.String(models.RpmV001SchemaPackageHashAlgorithmSha256),
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
			caseDesc: "public key with key content & with data with content",
			entry: V001Entry{
				RPMModel: models.RpmV001Schema{
					PublicKey: &models.RpmV001SchemaPublicKey{
						Content: strfmt.Base64(keyBytes),
					},
					Package: &models.RpmV001SchemaPackage{
						Content: strfmt.Base64(dataBytes),
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
				RPMModel: models.RpmV001Schema{
					PublicKey: &models.RpmV001SchemaPublicKey{
						Content: strfmt.Base64(keyBytes),
					},
					Package: &models.RpmV001SchemaPackage{
						Content: strfmt.Base64(dataBytes),
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
		r := models.Rpm{
			APIVersion: swag.String(tc.entry.APIVersion()),
			Spec:       tc.entry.RPMModel,
		}
		if err := v.Unmarshal(&r); (err == nil) != tc.expectUnmarshalSuccess {
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
