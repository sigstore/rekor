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

package rfc3161

import (
	"bytes"
	"context"
	"encoding/asn1"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/sassoftware/relic/lib/pkcs7"
	"github.com/sassoftware/relic/lib/pkcs9"

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
		caseDesc                     string
		entry                        V001Entry
		expectUnmarshalSuccess       bool
		expectCanonicalizeSuccess    bool
		expectValidationErrorMessage string
	}

	tsrBytes, _ := os.ReadFile("../tests/test.tsr")

	testServer := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			var file *[]byte
			var err error

			switch r.URL.Path {
			case "/data":
				file = &tsrBytes
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
			caseDesc:                     "empty obj",
			entry:                        V001Entry{},
			expectUnmarshalSuccess:       false,
			expectCanonicalizeSuccess:    false,
			expectValidationErrorMessage: "validation failure",
		},
		{
			caseDesc: "valid obj",
			entry: V001Entry{
				Rfc3161Obj: models.Rfc3161V001Schema{
					Tsr: &models.Rfc3161V001SchemaTsr{
						Content: p(tsrBytes),
					},
				},
			},
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
		},
		{
			caseDesc: "invalid obj - too big",
			entry: V001Entry{
				Rfc3161Obj: models.Rfc3161V001Schema{
					Tsr: &models.Rfc3161V001SchemaTsr{
						Content: p(tTooBig()),
					},
				},
			},
			expectUnmarshalSuccess:       false,
			expectCanonicalizeSuccess:    false,
			expectValidationErrorMessage: "tsr exceeds maximum allowed size (10kB)",
		},
		{
			caseDesc: "invalid obj - bad status",
			entry: V001Entry{
				Rfc3161Obj: models.Rfc3161V001Schema{
					Tsr: &models.Rfc3161V001SchemaTsr{
						Content: p(tBadStatus(t, tsrBytes)),
					},
				},
			},
			expectUnmarshalSuccess:       false,
			expectCanonicalizeSuccess:    false,
			expectValidationErrorMessage: "tsr status not granted: 2",
		},
		{
			caseDesc: "invalid obj - bad content type",
			entry: V001Entry{
				Rfc3161Obj: models.Rfc3161V001Schema{
					Tsr: &models.Rfc3161V001SchemaTsr{
						Content: p(tBadContentType(t, tsrBytes)),
					},
				},
			},
			expectUnmarshalSuccess:       false,
			expectCanonicalizeSuccess:    false,
			expectValidationErrorMessage: "tsr wrong content type: 0.0.0.0.42",
		},
		{
			caseDesc: "invalid obj - bad content",
			entry: V001Entry{
				Rfc3161Obj: models.Rfc3161V001Schema{
					Tsr: &models.Rfc3161V001SchemaTsr{
						Content: p(tBadContent(t, tsrBytes)),
					},
				},
			},
			expectUnmarshalSuccess:       false,
			expectCanonicalizeSuccess:    false,
			expectValidationErrorMessage: "tsr verification error",
		},
	}

	for _, tc := range testCases {
		v := &V001Entry{}
		ts := models.Rfc3161{
			APIVersion: swag.String(tc.entry.APIVersion()),
			Spec:       tc.entry.Rfc3161Obj,
		}

		if err := v.Unmarshal(&ts); (err == nil) != tc.expectUnmarshalSuccess {
			t.Errorf("unexpected result in '%v': %v", tc.caseDesc, err)
		} else if err != nil {
			if !strings.HasPrefix(err.Error(), tc.expectValidationErrorMessage) {
				t.Errorf("unexpected error message from Validate for '%v': %v", tc.caseDesc, err)
			}
		}

		if tc.expectUnmarshalSuccess {
			if ok, err := v.Insertable(); !ok || err != nil {
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
			// rfc3161 is one of two types that Insertable() should return true from canonicalized entries
			if ok, err := ei.Insertable(); !ok || err != nil {
				t.Errorf("unexpected error calling insertable on entry created from canonicalized content")
			}
		}
	}
}

func tTooBig() []byte {
	lotsOfBytes := make([]byte, 10*1024+1)
	for i := 0; i < len(lotsOfBytes); i++ {
		lotsOfBytes[i] = 1
	}
	return lotsOfBytes
}

func tBadStatus(t *testing.T, bytes []byte) []byte {
	var tsr pkcs9.TimeStampResp
	if _, err := asn1.Unmarshal(bytes, &tsr); err != nil {
		t.Fatal(err)
	}
	tsr.Status.Status = pkcs9.StatusRejection
	if b, err := asn1.Marshal(tsr); err != nil {
		t.Fatal(err)
	} else {
		return b
	}
	return nil
}

func tBadContentType(t *testing.T, bytes []byte) []byte {
	var tsr pkcs9.TimeStampResp
	if _, err := asn1.Unmarshal(bytes, &tsr); err != nil {
		t.Fatal(err)
	}
	tsr.TimeStampToken.ContentType = asn1.ObjectIdentifier{0, 0, 0, 0, 42}
	if b, err := asn1.Marshal(tsr); err != nil {
		t.Fatal(err)
	} else {
		return b
	}
	return nil
}

func tBadContent(t *testing.T, bytes []byte) []byte {
	var tsr pkcs9.TimeStampResp
	if _, err := asn1.Unmarshal(bytes, &tsr); err != nil {
		t.Fatal(err)
	}
	tsr.TimeStampToken.Content.Certificates = pkcs7.RawCertificates{}
	if b, err := asn1.Marshal(tsr); err != nil {
		t.Fatal(err)
	} else {
		return b
	}
	return nil
}

func p(b []byte) *strfmt.Base64 {
	b64 := strfmt.Base64(b)
	return &b64
}
