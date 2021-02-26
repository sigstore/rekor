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
	"context"
	"fmt"
	"sync"

	"github.com/sigstore/rekor/pkg/generated/models"
)

type TypeImpl interface {
	Kind() string
	UnmarshalEntry(pe models.ProposedEntry) (EntryImpl, error)
}

type EntryImpl interface {
	APIVersion() string
	IndexKeys() []string
	Canonicalize(ctx context.Context) ([]byte, error)
	FetchExternalEntities(ctx context.Context) error
	HasExternalEntities() bool
	Unmarshal(e models.ProposedEntry) error
}

type TypeFactory func() TypeImpl

type typeMap struct {
	typeImpls map[string]TypeFactory

	sync.RWMutex
}

func (tm *typeMap) Get(kind string) (TypeFactory, bool) {
	tm.RLock()
	defer tm.RUnlock()
	t, ok := tm.typeImpls[kind]
	return t, ok
}

func (tm *typeMap) Set(kind string, t TypeFactory) {
	tm.Lock()
	defer tm.Unlock()
	tm.typeImpls[kind] = t
}

var TypeMap = &typeMap{typeImpls: make(map[string]TypeFactory)}

func NewEntry(pe models.ProposedEntry) (EntryImpl, error) {
	if typeFactory, found := TypeMap.Get(pe.Kind()); found {
		t := typeFactory()
		if t == nil {
			return nil, fmt.Errorf("error generating object for kind '%v'", pe.Kind())
		}
		et, err := t.UnmarshalEntry(pe)
		if err != nil {
			return nil, err
		}
		return et, nil
	}
	return nil, fmt.Errorf("could not create entry for kind '%v'", pe.Kind())
}
