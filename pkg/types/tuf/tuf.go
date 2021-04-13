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
	"fmt"

	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/util"

	//"github.com/go-openapi/swag"
	"github.com/sigstore/rekor/pkg/generated/models"
)

const (
	KIND = "tuf"
)

type BaseTufType struct{}

func (rt BaseTufType) Kind() string {
	return KIND
}

func init() {
	types.TypeMap.Set(KIND, New)
}

func New() types.TypeImpl {
	return &BaseTufType{}
}

var SemVerToFacFnMap = &util.VersionFactoryMap{VersionFactories: make(map[string]util.VersionFactory)}

func (rt BaseTufType) UnmarshalEntry(pe models.ProposedEntry) (types.EntryImpl, error) {
	tuf, ok := pe.(*models.Tuf)
	if !ok {
		return nil, fmt.Errorf("cannot unmarshal non-tuf types %+v", pe)
	}

	if genFn, found := SemVerToFacFnMap.Get("0.0.1"); found {
		entry := genFn()
		if entry == nil {
			return nil, fmt.Errorf("failure generating tuf object for version '%v'", "0.0.1")
		}
		if err := entry.Unmarshal(tuf); err != nil {
			return nil, err
		}
		return entry, nil
	}
	return nil, fmt.Errorf("TufType implementation for version '%v' not found", "0.0.1")
}
