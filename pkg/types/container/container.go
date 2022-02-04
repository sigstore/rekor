//
// Copyright 2022 The Sigstore Authors.
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

package container

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
)

const (
	KIND = "container"
)

type BaseContainerType struct {
	types.RekorType
}

func init() {
	types.TypeMap.Store(KIND, New)
}

func New() types.TypeImpl {
	brt := BaseContainerType{}
	brt.Kind = KIND
	brt.VersionMap = VersionMap
	return &brt
}

var VersionMap = types.NewSemVerEntryFactoryMap()

func (rt BaseContainerType) UnmarshalEntry(pe models.ProposedEntry) (types.EntryImpl, error) {
	if pe == nil {
		return nil, errors.New("proposed entry cannot be nil")
	}

	container, ok := pe.(*models.Container)
	if !ok {
		return nil, errors.New(fmt.Sprintf("%s, %s", "cannot unmarshal non-container types", pe.Kind()))
	}

	return rt.VersionedUnmarshal(container, *container.APIVersion)
}

func (rt *BaseContainerType) CreateProposedEntry(ctx context.Context, version string, props types.ArtifactProperties) (models.ProposedEntry, error) {
	if version == "" {
		version = rt.DefaultVersion()
	}
	ei, err := rt.VersionedUnmarshal(nil, version)
	if err != nil {
		return nil, errors.Wrap(err, "fetching container version implementation")
	}

	return ei.CreateFromArtifactProperties(ctx, props)
}

func (rt BaseContainerType) DefaultVersion() string {
	return "0.0.1"
}
