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
	"errors"
	"fmt"
	"sync"

	"github.com/blang/semver"

	"github.com/projectrekor/rekor/pkg/log"
	"github.com/projectrekor/rekor/pkg/types"

	"github.com/go-openapi/swag"
	"github.com/projectrekor/rekor/pkg/generated/models"
)

const (
	KIND = "rekord"
)

type BaseRekordType struct{}

func (rt BaseRekordType) Kind() string {
	return KIND
}

func init() {
	types.TypeMap.Set(KIND, BaseRekordType{})
}

type versionFuncMap struct {
	versionFuncs map[string]interface{}

	sync.RWMutex
}

func (vfm *versionFuncMap) Get(version string) (interface{}, bool) {
	vfm.RLock()
	defer vfm.RUnlock()

	semverToMatch, err := semver.Parse(version)
	if err != nil {
		log.Logger.Error(err)
		return nil, false
	}

	//will return first function that matches
	for k, v := range vfm.versionFuncs {
		semverRange, err := semver.ParseRange(k)
		if err != nil {
			log.Logger.Error(err)
			return nil, false
		}

		if semverRange(semverToMatch) {
			return v, true
		}
	}
	return nil, false
}

func (vfm *versionFuncMap) Set(constraint string, f interface{}) {
	vfm.Lock()
	defer vfm.Unlock()

	if _, err := semver.ParseRange(constraint); err != nil {
		log.Logger.Error(err)
		return
	}

	vfm.versionFuncs[constraint] = f
}

var SemVerToGenFnMap = &versionFuncMap{versionFuncs: make(map[string]interface{})}

func (rt BaseRekordType) UnmarshalEntry(pe interface{}) (*types.EntryImpl, error) {
	rekord, ok := pe.(*models.Rekord)
	if !ok {
		return nil, errors.New("cannot unmarshal non-Rekord types")
	}

	if genFn, found := SemVerToGenFnMap.Get(swag.StringValue(rekord.APIVersion)); found {
		entry := genFn.(func() interface{})().(types.EntryImpl)
		if err := entry.Unmarshal(*rekord); err != nil {
			return nil, err
		}
		return &entry, nil
	}
	return nil, fmt.Errorf("RekordType implementation for version '%v' not found", swag.StringValue(rekord.APIVersion))
}
