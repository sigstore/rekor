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

package util

import (
	"sync"

	"github.com/blang/semver"

	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/types"
)

type VersionFactory func() types.EntryImpl

type VersionFactoryMap struct {
	VersionFactories map[string]VersionFactory

	sync.RWMutex
}

func (vfm *VersionFactoryMap) Get(version string) (VersionFactory, bool) {
	vfm.RLock()
	defer vfm.RUnlock()

	semverToMatch, err := semver.Parse(version)
	if err != nil {
		log.Logger.Error(err)
		return nil, false
	}

	// will return first function that matches
	for k, v := range vfm.VersionFactories {
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

func (vfm *VersionFactoryMap) Set(constraint string, vf VersionFactory) {
	vfm.Lock()
	defer vfm.Unlock()

	if _, err := semver.ParseRange(constraint); err != nil {
		log.Logger.Error(err)
		return
	}

	vfm.VersionFactories[constraint] = vf
}
