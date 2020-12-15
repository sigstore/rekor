/*
Copyright © 2020 Bob Callaway <bcallawa@redhat.com>

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

package rekord

import (
	"context"
	"errors"
	"testing"

	"github.com/go-openapi/swag"
	"github.com/projectrekor/rekor/pkg/generated/models"
)

type UnmarshalTester struct {
	models.Rekord
	unmarshalError bool
}

func NewUnmarshalTester() interface{} {
	return &UnmarshalTester{}
}

func NewUnmarshalFailsTester() interface{} {
	return &UnmarshalTester{unmarshalError: true}
}

func (u UnmarshalTester) APIVersion() string {
	return "2.0.1"
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

func (u UnmarshalTester) Unmarshal(e interface{}) error {
	if u.unmarshalError {
		return errors.New("error")
	}
	return nil
}

func TestRekordType(t *testing.T) {
	// empty to start
	if len(SemVerToGenFnMap.versionFuncs) != 0 {
		t.Error("semver range was not blank at start of test")
	}

	// ensure semver range parser is working
	invalidSemVerRange := "not a valid semver range"
	SemVerToGenFnMap.Set(invalidSemVerRange, &invalidSemVerRange)
	if len(SemVerToGenFnMap.versionFuncs) > 0 {
		t.Error("invalid semver range was incorrectly added to SemVerToGenFnMap")
	}

	// valid semver range can be parsed
	u := UnmarshalTester{unmarshalError: false}
	SemVerToGenFnMap.Set(">= 1.2.3", NewUnmarshalTester)
	if len(SemVerToGenFnMap.versionFuncs) != 1 {
		t.Error("valid semver range was not added to SemVerToGenFnMap")
	}

	u.Rekord.APIVersion = swag.String("2.0.1")
	brt := BaseRekordType{}

	// pass a non-Rekord object and ensure unmarshal fails
	if _, err := brt.UnmarshalEntry(swag.String("not_rekord")); err == nil {
		t.Error("unexpected success Unmarshalling non Rekord object")
	}

	// version requested matches implementation in map
	if _, err := brt.UnmarshalEntry(&u.Rekord); err != nil {
		t.Errorf("unexpected error in Unmarshal: %v", err)
	}

	// version requested fails to match implementation in map
	u.Rekord.APIVersion = swag.String("1.2.2")
	if _, err := brt.UnmarshalEntry(&u.Rekord); err == nil {
		t.Error("unexpected success in Unmarshal for non-matching version")
	}

	// error in Unmarshal call is raised appropriately
	u.Rekord.APIVersion = swag.String("2.2.0")
	SemVerToGenFnMap.Set(">= 1.2.3", NewUnmarshalFailsTester)
	if _, err := brt.UnmarshalEntry(&u.Rekord); err == nil {
		t.Error("unexpected success in Unmarshal when error is thrown")
	}

	// version requested fails to match implementation in map
	u.Rekord.APIVersion = swag.String("not_a_version")
	if _, err := brt.UnmarshalEntry(&u.Rekord); err == nil {
		t.Error("unexpected success in Unmarshal for invalid version")
	}
}
