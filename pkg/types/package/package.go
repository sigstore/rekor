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

package _package

import (
	"context"

	"github.com/pkg/errors"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
)

const (
	KIND = "package"
)

type BasePackageType struct {
	types.RekorType
}

func init() {
	types.TypeMap.Store(KIND, New)
}

func New() types.TypeImpl {
	pkg := BasePackageType{}
	pkg.Kind = KIND
	pkg.VersionMap = VersionMap
	return &pkg
}

var VersionMap = types.NewSemVerEntryFactoryMap()

func (bpt *BasePackageType) CreateProposedEntry(ctx context.Context, version string, props types.ArtifactProperties) (models.ProposedEntry, error) {
	if version == "" {
		version = bpt.DefaultVersion()
	}
	epkg, err := bpt.VersionedUnmarshal(nil, version)
	if err != nil {
		return nil, errors.Wrap(err, "fetching Package version implementation")
	}
	return epkg.CreateFromArtifactProperties(ctx, props)
}

func (bpt BasePackageType) DefaultVersion() string {
	return "0.0.1"
}

func (bpt BasePackageType) UnmarshalEntry(pe models.ProposedEntry) (types.EntryImpl, error) {
	if pe == nil {
		return nil, errors.New("proposed entry cannot be nil")
	}

	pkg, ok := pe.(*models.Package)
	if !ok {
		return nil, errors.New("cannot unmarshal non-Package types")
	}

	return bpt.VersionedUnmarshal(pkg, *pkg.APIVersion)
}
