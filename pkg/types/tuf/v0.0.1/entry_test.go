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
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/swag"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/verify"

	"go.uber.org/goleak"
)

func patchIsExpired() func() {
	// Patch out the IsExpired to make the tests stable :)
	old := verify.IsExpired
	verify.IsExpired = func(t time.Time) bool {
		return false
	}
	return func() {
		verify.IsExpired = old
	}
}

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
	defer patchIsExpired()()

	type TestCase struct {
		caseDesc                  string
		entry                     V001Entry
		expectUnmarshalSuccess    bool
		expectCanonicalizeSuccess bool
	}

	keyBytes, _ := os.ReadFile("../../../../tests/test_root.json")
	dataBytes, _ := os.ReadFile("../../../../tests/test_timestamp.json")
	anyBytes, _ := os.ReadFile("../../../../tests/test_any.json")

	keyContent := &data.Signed{}
	if err := json.Unmarshal(keyBytes, keyContent); err != nil {
		t.Errorf("unexpected error")
	}
	dataContent := &data.Signed{}
	if err := json.Unmarshal(dataBytes, dataContent); err != nil {
		t.Errorf("unexpected error")
	}
	anyContent := &data.Signed{}
	if err := json.Unmarshal(anyBytes, anyContent); err != nil {
		t.Errorf("unexpected error")
	}

	testCases := []TestCase{
		{
			caseDesc: "root without content",
			entry: V001Entry{
				TufObj: models.TUFV001Schema{
					Root:     &models.TUFV001SchemaRoot{},
					Metadata: &models.TUFV001SchemaMetadata{},
				},
			},
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "root without manifest",
			entry: V001Entry{
				TufObj: models.TUFV001Schema{
					Root: &models.TUFV001SchemaRoot{
						Content: keyContent,
					},
					Metadata: &models.TUFV001SchemaMetadata{},
				},
			},
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "root with invalid manifest & valid metadata",
			entry: V001Entry{
				TufObj: models.TUFV001Schema{
					Root: &models.TUFV001SchemaRoot{
						Content: anyContent,
					},
					Metadata: &models.TUFV001SchemaMetadata{
						Content: dataContent,
					},
				},
			},
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
		},
		{
			caseDesc: "root with manifest & content",
			entry: V001Entry{
				TufObj: models.TUFV001Schema{
					Root: &models.TUFV001SchemaRoot{
						Content: keyContent,
					},
					Metadata: &models.TUFV001SchemaMetadata{
						Content: dataContent,
					},
				},
			},
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
		},
		{
			caseDesc: "root with invalid key content & with manifest with content",
			entry: V001Entry{
				TufObj: models.TUFV001Schema{
					Root: &models.TUFV001SchemaRoot{
						Content: dataContent,
					},
					Metadata: &models.TUFV001SchemaMetadata{
						Content: dataContent,
					},
				},
			},
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
		},
		{
			caseDesc: "public key with key content & with invalid data with content",
			entry: V001Entry{
				TufObj: models.TUFV001Schema{
					Root: &models.TUFV001SchemaRoot{
						Content: keyContent,
					},
					Metadata: &models.TUFV001SchemaMetadata{
						Content: anyContent,
					},
				},
			},
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
		},
	}

	for _, tc := range testCases {
		if err := tc.entry.Validate(); (err == nil) != tc.expectUnmarshalSuccess {
			t.Errorf("unexpected result in '%v': %v", tc.caseDesc, err)
		}
		// No need to continue here if we failed at unmarshal
		if !tc.expectUnmarshalSuccess {
			continue
		}

		v := &V001Entry{}
		r := models.TUF{
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
	}
}
