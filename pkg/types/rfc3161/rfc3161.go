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

package rfc3161

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
)

const (
	KIND = "rfc3161"
)

type BaseTimestampType struct {
	types.RekorType
}

func init() {
	types.TypeMap.Store(KIND, New)
}

func New() types.TypeImpl {
	btt := BaseTimestampType{}
	btt.Kind = KIND
	btt.VersionMap = VersionMap
	return &btt
}

var VersionMap = types.NewSemVerEntryFactoryMap()

func (btt BaseTimestampType) UnmarshalEntry(pe models.ProposedEntry) (types.EntryImpl, error) {
	if pe == nil {
		return nil, errors.New("proposed entry cannot be nil")
	}

	rfc3161, ok := pe.(*models.Rfc3161)
	if !ok {
		return nil, errors.New("cannot unmarshal non-Timestamp types")
	}

	return btt.VersionedUnmarshal(rfc3161, *rfc3161.APIVersion)
}

func (btt *BaseTimestampType) CreateProposedEntry(ctx context.Context, version string, props types.ArtifactProperties) (models.ProposedEntry, error) {
	if version == "" {
		version = btt.DefaultVersion()
	}
	ei, err := btt.VersionedUnmarshal(nil, version)
	if err != nil {
		return nil, fmt.Errorf("fetching RFC3161 version implementation: %w", err)
	}
	return ei.CreateFromArtifactProperties(ctx, props)
}

func (btt BaseTimestampType) DefaultVersion() string {
	return "0.0.1"
}
