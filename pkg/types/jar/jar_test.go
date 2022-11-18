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
	"errors"
	"testing"

	"github.com/go-openapi/swag"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/types"
)

type UnmarshalTester struct {
	models.Jar
	types.BaseUnmarshalTester
}

type UnmarshalFailsTester struct {
	types.BaseUnmarshalTester
}

func (u UnmarshalFailsTester) NewEntry() types.EntryImpl {
	return &UnmarshalFailsTester{}
}

func (u UnmarshalFailsTester) Unmarshal(pe models.ProposedEntry) error {
	return errors.New("error")
}

func (u UnmarshalFailsTester) Verifier() (pki.PublicKey, error) {
	return nil, nil
}

func TestJARType(t *testing.T) {
	// empty to start
	if VersionMap.Count() != 0 {
		t.Error("semver range was not blank at start of test")
	}

	u := UnmarshalTester{}
	// ensure semver range parser is working
	invalidSemVerRange := "not a valid semver range"
	VersionMap.SetEntryFactory(invalidSemVerRange, u.NewEntry)
	if VersionMap.Count() > 0 {
		t.Error("invalid semver range was incorrectly added to SemVerToFacFnMap")
	}

	// valid semver range can be parsed
	VersionMap.SetEntryFactory(">= 1.2.3", u.NewEntry)
	if VersionMap.Count() != 1 {
		t.Error("valid semver range was not added to SemVerToFacFnMap")
	}

	u.Jar.APIVersion = swag.String("2.0.1")
	brt := New()

	// version requested matches implementation in map
	if _, err := brt.UnmarshalEntry(&u.Jar); err != nil {
		t.Errorf("unexpected error in Unmarshal: %v", err)
	}

	// version requested fails to match implementation in map
	u.Jar.APIVersion = swag.String("1.2.2")
	if _, err := brt.UnmarshalEntry(&u.Jar); err == nil {
		t.Error("unexpected success in Unmarshal for non-matching version")
	}

	// error in Unmarshal call is raised appropriately
	u.Jar.APIVersion = swag.String("2.2.0")
	u2 := UnmarshalFailsTester{}
	VersionMap.SetEntryFactory(">= 1.2.3", u2.NewEntry)
	if _, err := brt.UnmarshalEntry(&u.Jar); err == nil {
		t.Error("unexpected success in Unmarshal when error is thrown")
	}

	// version requested fails to match implementation in map
	u.Jar.APIVersion = swag.String("not_a_version")
	if _, err := brt.UnmarshalEntry(&u.Jar); err == nil {
		t.Error("unexpected success in Unmarshal for invalid version")
	}
}
