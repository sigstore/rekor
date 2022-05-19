/*
Copyright © 2021 The Sigstore Authors.

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
	"context"
	"fmt"

	"github.com/pkg/errors"
	"github.com/sigstore/rekor/pkg/types"

	"github.com/sigstore/rekor/pkg/generated/models"
)

const (
	KIND = "tuf"
)

type BaseTufType struct {
	types.RekorType
}

func init() {
	types.TypeMap.Store(KIND, New)
}

func New() types.TypeImpl {
	btt := BaseTufType{}
	btt.Kind = KIND
	btt.VersionMap = VersionMap
	return &btt
}

var VersionMap = types.NewSemVerEntryFactoryMap()

func (btt BaseTufType) UnmarshalEntry(pe models.ProposedEntry) (types.EntryImpl, error) {
	if pe == nil {
		return nil, errors.New("proposed entry cannot be nil")
	}

	tuf, ok := pe.(*models.TUF)
	if !ok {
		return nil, fmt.Errorf("cannot unmarshal non-tuf types %+v", pe)
	}

	return btt.VersionedUnmarshal(tuf, *tuf.APIVersion)
}

func (btt *BaseTufType) CreateProposedEntry(ctx context.Context, version string, props types.ArtifactProperties) (models.ProposedEntry, error) {
	if version == "" {
		version = btt.DefaultVersion()
	}
	ei, err := btt.VersionedUnmarshal(nil, version)
	if err != nil {
		return nil, fmt.Errorf("fetching TUF version implementation: %w", err)
	}
	return ei.CreateFromArtifactProperties(ctx, props)
}

func (btt BaseTufType) DefaultVersion() string {
	return "0.0.1"
}
