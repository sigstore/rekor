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

package dsse

import (
	"context"
	"errors"
	"fmt"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
)

const (
	KIND = "dsse"
)

type BaseDsseType struct {
	types.RekorType
}

func init() {
	types.TypeMap.Store(KIND, New)
}

func New() types.TypeImpl {
	bdt := BaseDsseType{}
	bdt.Kind = KIND
	bdt.VersionMap = VersionMap
	return &bdt
}

var VersionMap = types.NewSemVerEntryFactoryMap()

func (bdt BaseDsseType) UnmarshalEntry(pe models.ProposedEntry) (types.EntryImpl, error) {
	if pe == nil {
		return nil, errors.New("proposed entry cannot be nil")
	}

	in, ok := pe.(*models.Dsse)
	if !ok {
		return nil, errors.New("cannot unmarshal non-DSSE types")
	}

	return bdt.VersionedUnmarshal(in, *in.APIVersion)
}

func (bdt *BaseDsseType) CreateProposedEntry(ctx context.Context, version string, props types.ArtifactProperties) (models.ProposedEntry, error) {
	if version == "" {
		version = bdt.DefaultVersion()
	}
	ei, err := bdt.VersionedUnmarshal(nil, version)
	if err != nil {
		return nil, fmt.Errorf("fetching DSSE version implementation, %w", err)
	}

	return ei.CreateFromArtifactProperties(ctx, props)
}

func (bdt BaseDsseType) DefaultVersion() string {
	return "0.0.1"
}
