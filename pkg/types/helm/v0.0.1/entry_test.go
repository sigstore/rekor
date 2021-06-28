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
	"context"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"go.uber.org/goleak"

	"github.com/sigstore/rekor/pkg/generated/models"
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

	keyBytes, _ := ioutil.ReadFile("../../../../tests/test_helm_armor.pub")
	provenanceBytes, _ := ioutil.ReadFile("../../../../tests/test-0.1.0.tgz.prov")

	testServer := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			var file *[]byte
			var err error

			switch r.URL.Path {
			case "/key":
				file = &keyBytes
			case "/provenance":
				file = &provenanceBytes
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
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "public key without provenance file",
			entry: V001Entry{
				HelmObj: models.HelmV001Schema{
					PublicKey: &models.HelmV001SchemaPublicKey{
						Content: strfmt.Base64(keyBytes),
					},
				},
			},
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "public key with empty provenance file",
			entry: V001Entry{
				HelmObj: models.HelmV001Schema{
					PublicKey: &models.HelmV001SchemaPublicKey{
						URL: strfmt.URI(testServer.URL + "/key"),
					},
					Chart: &models.HelmV001SchemaChart{
						Provenance: &models.HelmV001SchemaChartProvenance{},
					},
				},
			},
			expectUnmarshalSuccess: false,
			hasExtEntities:         true,
		},
		{
			caseDesc: "provenance file with 404 on public key",
			entry: V001Entry{
				HelmObj: models.HelmV001Schema{
					PublicKey: &models.HelmV001SchemaPublicKey{
						URL: strfmt.URI(testServer.URL + "/404"),
					},
					Chart: &models.HelmV001SchemaChart{
						Provenance: &models.HelmV001SchemaChartProvenance{
							Content: strfmt.Base64(provenanceBytes),
						},
					},
				},
			},
			expectUnmarshalSuccess:    true,
			hasExtEntities:            true,
			expectCanonicalizeSuccess: false,
		},
		{
			caseDesc: "public key with 404 on provenance file",
			entry: V001Entry{
				HelmObj: models.HelmV001Schema{
					PublicKey: &models.HelmV001SchemaPublicKey{
						Content: strfmt.Base64(keyBytes),
					},
					Chart: &models.HelmV001SchemaChart{
						Provenance: &models.HelmV001SchemaChartProvenance{
							URL: strfmt.URI(testServer.URL + "/404"),
						},
					},
				},
			},
			expectUnmarshalSuccess:    true,
			hasExtEntities:            true,
			expectCanonicalizeSuccess: false,
		},
		{
			caseDesc: "public key and invalid provenance content",
			entry: V001Entry{
				HelmObj: models.HelmV001Schema{
					PublicKey: &models.HelmV001SchemaPublicKey{
						Content: strfmt.Base64(keyBytes),
					},
					Chart: &models.HelmV001SchemaChart{
						Provenance: &models.HelmV001SchemaChartProvenance{
							Content: strfmt.Base64(keyBytes),
						},
					},
				},
			},
			expectUnmarshalSuccess:    true,
			hasExtEntities:            false,
			expectCanonicalizeSuccess: false,
		},
		{
			caseDesc: "provenance content with invalid public key",
			entry: V001Entry{
				HelmObj: models.HelmV001Schema{
					PublicKey: &models.HelmV001SchemaPublicKey{
						Content: strfmt.Base64(provenanceBytes),
					},
					Chart: &models.HelmV001SchemaChart{
						Provenance: &models.HelmV001SchemaChartProvenance{
							Content: strfmt.Base64(provenanceBytes),
						},
					},
				},
			},
			expectUnmarshalSuccess:    true,
			hasExtEntities:            false,
			expectCanonicalizeSuccess: false,
		},
		{
			caseDesc: "provenance content with invalid public key",
			entry: V001Entry{
				HelmObj: models.HelmV001Schema{
					PublicKey: &models.HelmV001SchemaPublicKey{
						Content: strfmt.Base64(keyBytes),
					},
					Chart: &models.HelmV001SchemaChart{
						Provenance: &models.HelmV001SchemaChartProvenance{
							Content: strfmt.Base64(provenanceBytes),
						},
					},
				},
			},
			expectUnmarshalSuccess:    true,
			hasExtEntities:            false,
			expectCanonicalizeSuccess: true,
		},
	}

	for _, tc := range testCases {
		if err := tc.entry.Validate(); (err == nil) != tc.expectUnmarshalSuccess {
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
			if err := v.Validate(); err != nil {
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

		if _, err := tc.entry.Canonicalize(context.TODO()); (err == nil) != tc.expectCanonicalizeSuccess {
			t.Errorf("unexpected result from Canonicalize for '%v': %v", tc.caseDesc, err)
		}
	}
}
