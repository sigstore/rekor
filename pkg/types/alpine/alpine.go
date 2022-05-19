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

package alpine

import (
	"context"
	"errors"
	"fmt"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
)

const (
	KIND = "alpine"
)

type BaseAlpineType struct {
	types.RekorType
}

func init() {
	types.TypeMap.Store(KIND, New)
}

func New() types.TypeImpl {
	bat := BaseAlpineType{}
	bat.Kind = KIND
	bat.VersionMap = VersionMap
	return &bat
}

var VersionMap = types.NewSemVerEntryFactoryMap()

func (bat *BaseAlpineType) UnmarshalEntry(pe models.ProposedEntry) (types.EntryImpl, error) {
	if pe == nil {
		return nil, errors.New("proposed entry cannot be nil")
	}

	apk, ok := pe.(*models.Alpine)
	if !ok {
		return nil, errors.New("cannot unmarshal non-Alpine types")
	}

	return bat.VersionedUnmarshal(apk, *apk.APIVersion)
}

func (bat *BaseAlpineType) CreateProposedEntry(ctx context.Context, version string, props types.ArtifactProperties) (models.ProposedEntry, error) {
	if version == "" {
		version = bat.DefaultVersion()
	}
	ei, err := bat.VersionedUnmarshal(nil, version)
	if err != nil {
		return nil, fmt.Errorf("fetching Intoto version implementation: %w", err)
	}
	return ei.CreateFromArtifactProperties(ctx, props)
}

func (bat BaseAlpineType) DefaultVersion() string {
	return "0.0.1"
}
