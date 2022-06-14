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

package cose

import (
	"context"

	"github.com/pkg/errors"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
)

const (
	KIND = "cose"
)

type BaseCOSEType struct {
	types.RekorType
}

func init() {
	types.TypeMap.Store(KIND, New)
}

func New() types.TypeImpl {
	bit := BaseCOSEType{}
	bit.Kind = KIND
	bit.VersionMap = VersionMap
	return &bit
}

var VersionMap = types.NewSemVerEntryFactoryMap()

func (it BaseCOSEType) UnmarshalEntry(pe models.ProposedEntry) (types.EntryImpl, error) {
	if pe == nil {
		return nil, errors.New("proposed entry cannot be nil")
	}

	in, ok := pe.(*models.Cose)
	if !ok {
		return nil, errors.New("cannot unmarshal non-COSE types")
	}

	return it.VersionedUnmarshal(in, *in.APIVersion)
}

func (it *BaseCOSEType) CreateProposedEntry(ctx context.Context, version string, props types.ArtifactProperties) (models.ProposedEntry, error) {
	if version == "" {
		version = it.DefaultVersion()
	}
	ei, err := it.VersionedUnmarshal(nil, version)
	if err != nil {
		return nil, errors.Wrap(err, "fetching COSE version implementation")
	}
	return ei.CreateFromArtifactProperties(ctx, props)
}

func (it BaseCOSEType) DefaultVersion() string {
	return "0.0.1"
}
