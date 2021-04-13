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

package tuf

import (
	"context"
	"errors"
	"testing"

	"github.com/go-openapi/swag"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
)

type UnmarshalTester struct {
	models.InToto
}

func (u UnmarshalTester) NewEntry() types.EntryImpl {
	return &UnmarshalTester{}
}

func (u UnmarshalTester) APIVersion() string {
	return "2.0.1"
}

func (u UnmarshalTester) IndexKeys() []string {
	return []string{}
}

func (u UnmarshalTester) Canonicalize(ctx context.Context) ([]byte, error) {
	return nil, nil
}

func (u UnmarshalTester) HasExternalEntities() bool {
	return false
}

func (u *UnmarshalTester) FetchExternalEntities(ctx context.Context) error {
	return nil
}

func (u UnmarshalTester) Unmarshal(pe models.ProposedEntry) error {
	return nil
}

type UnmarshalFailsTester struct {
	UnmarshalTester
}

func (u UnmarshalFailsTester) NewEntry() types.EntryImpl {
	return &UnmarshalFailsTester{}
}

func (u UnmarshalFailsTester) Unmarshal(pe models.ProposedEntry) error {
	return errors.New("error")
}

func TestInTotoType(t *testing.T) {
	// empty to start
	if len(SemVerToFacFnMap.VersionFactories) != 0 {
		t.Error("semver range was not blank at start of test")
	}

	u := UnmarshalTester{}
	// ensure semver range parser is working
	invalidSemVerRange := "not a valid semver range"
	SemVerToFacFnMap.Set(invalidSemVerRange, u.NewEntry)
	if len(SemVerToFacFnMap.VersionFactories) > 0 {
		t.Error("invalid semver range was incorrectly added to SemVerToFacFnMap")
	}

	// valid semver range can be parsed
	SemVerToFacFnMap.Set(">= 1.2.3", u.NewEntry)
	if len(SemVerToFacFnMap.VersionFactories) != 1 {
		t.Error("valid semver range was not added to SemVerToFacFnMap")
	}

	u.InToto.APIVersion = swag.String("2.0.1")
	brt := BaseInTotoType{}

	// version requested matches implementation in map
	if _, err := brt.UnmarshalEntry(&u.InToto); err != nil {
		t.Errorf("unexpected error in Unmarshal: %v", err)
	}

	// version requested fails to match implementation in map
	u.InToto.APIVersion = swag.String("1.2.2")
	if _, err := brt.UnmarshalEntry(&u.InToto); err == nil {
		t.Error("unexpected success in Unmarshal for non-matching version")
	}

	// error in Unmarshal call is raised appropriately
	u.InToto.APIVersion = swag.String("2.2.0")
	u2 := UnmarshalFailsTester{}
	SemVerToFacFnMap.Set(">= 1.2.3", u2.NewEntry)
	if _, err := brt.UnmarshalEntry(&u.InToto); err == nil {
		t.Error("unexpected success in Unmarshal when error is thrown")
	}

	// version requested fails to match implementation in map
	u.InToto.APIVersion = swag.String("not_a_version")
	if _, err := brt.UnmarshalEntry(&u.InToto); err == nil {
		t.Error("unexpected success in Unmarshal for invalid version")
	}
}
