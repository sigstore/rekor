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

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
)

const (
	KIND = "jar"
)

type BaseJARType struct {
	types.RekorType
}

func init() {
	types.TypeMap.Store(KIND, New)
}

func New() types.TypeImpl {
	bjt := BaseJARType{}
	bjt.Kind = KIND
	bjt.VersionMap = VersionMap
	return &bjt
}

var VersionMap = types.NewSemVerEntryFactoryMap()

func (bjt *BaseJARType) UnmarshalEntry(pe models.ProposedEntry) (types.EntryImpl, error) {
	if pe == nil {
		return nil, errors.New("proposed entry cannot be nil")
	}

	jar, ok := pe.(*models.Jar)
	if !ok {
		return nil, errors.New("cannot unmarshal non-JAR types")
	}

	return bjt.VersionedUnmarshal(jar, *jar.APIVersion)
}
