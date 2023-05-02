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

package jar

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/spf13/viper"
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
		expectUnmarshalSuccess    bool
		expectCanonicalizeSuccess bool
		expectedVerifierSuccess   bool
	}

	jarBytes, _ := os.ReadFile("tests/test.jar")
	// extracted from jar
	certificate := `-----BEGIN CERTIFICATE-----
MIIB+DCCAX6gAwIBAgITNVkDZoCiofPDsy7dfm6geLbuhzAKBggqhkjOPQQDAzAq
MRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIx
MDMwNzAzMjAyOVoXDTMxMDIyMzAzMjAyOVowKjEVMBMGA1UEChMMc2lnc3RvcmUu
ZGV2MREwDwYDVQQDEwhzaWdzdG9yZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLSy
A7Ii5k+pNO8ZEWY0ylemWDowOkNa3kL+GZE5Z5GWehL9/A9bRNA3RbrsZ5i0Jcas
taRL7Sp5fp/jD5dxqc/UdTVnlvS16an+2Yfswe/QuLolRUCrcOE2+2iA5+tzd6Nm
MGQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYE
FMjFHQBBmiQpMlEk6w2uSu1KBtPsMB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2u
Su1KBtPsMAoGCCqGSM49BAMDA2gAMGUCMH8liWJfMui6vXXBhjDgY4MwslmN/TJx
Ve/83WrFomwmNf056y1X48F9c4m3a3ozXAIxAKjRay5/aj/jsKKGIkmQatjI8uup
Hr/+CxFvaJWmpYqNkLDGRU+9orzh5hI2RrcuaQ==
-----END CERTIFICATE-----
`

	testCases := []TestCase{
		{
			caseDesc:                "empty obj",
			entry:                   V001Entry{},
			expectUnmarshalSuccess:  false,
			expectedVerifierSuccess: false,
		},
		{
			caseDesc: "empty archive",
			entry: V001Entry{
				JARModel: models.JarV001Schema{
					Archive: &models.JarV001SchemaArchive{},
				},
			},
			expectUnmarshalSuccess:  false,
			expectedVerifierSuccess: false,
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
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
			expectedVerifierSuccess:   true,
		},
	}

	for _, tc := range testCases {
		v := &V001Entry{}
		r := models.Jar{
			APIVersion: swag.String(tc.entry.APIVersion()),
			Spec:       tc.entry.JARModel,
		}

		if err := v.Unmarshal(&r); (err == nil) != tc.expectUnmarshalSuccess {
			t.Errorf("unexpected result in '%v': %v", tc.caseDesc, err)
		}
		// No need to continue here if unmarshal failed
		if !tc.expectUnmarshalSuccess {
			continue
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

		verifier, err := v.Verifier()
		if tc.expectedVerifierSuccess {
			if err != nil {
				t.Errorf("%v: unexpected error, got %v", tc.caseDesc, err)
			} else {
				pub, _ := verifier.CanonicalValue()
				if !reflect.DeepEqual(pub, []byte(certificate)) {
					t.Errorf("verifier and public keys do not match: %v, %v", string(pub), certificate)
				}
			}
		} else {
			if err == nil {
				s, _ := verifier.CanonicalValue()
				t.Errorf("%v: expected error for %v, got %v", tc.caseDesc, string(s), err)
			}
		}
	}
}

func TestJarMetadataSize(t *testing.T) {
	type TestCase struct {
		caseDesc                  string
		entry                     V001Entry
		expectUnmarshalSuccess    bool
		expectCanonicalizeSuccess bool
		expectedVerifierSuccess   bool
	}

	jarBytes, _ := os.ReadFile("tests/test.jar")

	os.Setenv("MAX_JAR_METADATA_SIZE", "10")
	viper.AutomaticEnv()

	v := V001Entry{
		JARModel: models.JarV001Schema{
			Archive: &models.JarV001SchemaArchive{
				Content: strfmt.Base64(jarBytes),
			},
		},
	}

	r := models.Jar{
		APIVersion: swag.String(v.APIVersion()),
		Spec:       v.JARModel,
	}

	if err := v.Unmarshal(&r); err != nil {
		t.Errorf("unexpected unmarshal failure: %v", err)
	}

	_, err := v.Canonicalize(context.TODO())
	if err == nil {
		t.Fatal("expecting metadata too large err")
	}
	if !strings.Contains(err.Error(), "exceeds max allowed size 10") {
		t.Fatalf("unexpected error %v", err)
	}
}
