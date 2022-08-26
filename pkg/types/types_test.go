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

package types

import (
	"context"
	"errors"
	"testing"

	"github.com/go-openapi/strfmt"
	"go.uber.org/goleak"

	"github.com/sigstore/rekor/pkg/generated/models"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

type InvalidEntry struct{}

func (e InvalidEntry) Kind() string {
	return "invalid"
}

func (e InvalidEntry) SetKind(string) {}

func (e InvalidEntry) Validate(formats strfmt.Registry) error {
	return nil
}

func (e InvalidEntry) ContextValidate(context context.Context, formats strfmt.Registry) error {
	return nil
}

type UnmarshalErrorValidEntry struct{}

func (e UnmarshalErrorValidEntry) Kind() string {
	if _, found := TypeMap.Load("rekord"); found {
		return "rekord"
	}
	return ""
}

func (e UnmarshalErrorValidEntry) SetKind(string) {}

func (e UnmarshalErrorValidEntry) Validate(formats strfmt.Registry) error {
	return errors.New("invalid content")
}

func (e UnmarshalErrorValidEntry) ContextValidate(context context.Context, formats strfmt.Registry) error {
	return nil
}

func TestUnmarshalEntry(t *testing.T) {
	type TestCase struct {
		entry         models.ProposedEntry
		expectSuccess bool
	}

	testCases := []TestCase{
		{
			entry:         InvalidEntry{},
			expectSuccess: false,
		},
		{
			entry:         UnmarshalErrorValidEntry{},
			expectSuccess: false,
		},
	}

	for _, tc := range testCases {
		if _, err := UnmarshalEntry(tc.entry); (err == nil) != tc.expectSuccess {
			t.Errorf("unexpected error creating entry of type '%v': %v", tc.entry.Kind(), err)
		}
	}
}
