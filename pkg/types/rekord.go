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
package types

import (
	"fmt"
	"reflect"

	"github.com/projectrekor/rekor/pkg/generated/models"
	rekord_v001 "github.com/projectrekor/rekor/pkg/types/rekord/v0.0.1"
)

type RekordType struct {
	r models.Rekord
}

func (rt RekordType) Kind() string {
	return rt.r.Kind()
}

var versionToEntryTypeMap = map[string]reflect.Type{}

func init() {
	// add new versions here
	versions := []EntryImpl{
		rekord_v001.V001Entry{},
	}

	for _, version := range versions {
		versionToEntryTypeMap[version.APIVersion()] = reflect.TypeOf(version)
	}
}

func (rt RekordType) UnmarshalEntry(pe interface{}) (*EntryImpl, error) {
	rekord := pe.(*models.Rekord)
	if et, found := versionToEntryTypeMap[*rekord.APIVersion]; found {
		entry := reflect.Zero(et).Interface().(EntryImpl)
		if err := entry.Unmarshal(rekord); err != nil {
			return nil, err
		}
		return &entry, nil
	}
	return nil, fmt.Errorf("RekordType implementation for version '%v' not found", *rekord.APIVersion)
}
