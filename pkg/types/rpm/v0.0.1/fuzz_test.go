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

package rpm

import (
	"context"
	"sync"
	"testing"

	fuzz "github.com/AdamKorcz/go-fuzz-headers-1"
	"github.com/go-openapi/swag"

	fuzzUtils "github.com/sigstore/rekor/pkg/fuzz"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/rpm"
)

var initter sync.Once

func FuzzRpmCreateProposedEntry(f *testing.F) {
	f.Fuzz(func(t *testing.T, propsData []byte) {
		initter.Do(fuzzUtils.SetFuzzLogger)

		version := "0.0.1"

		ff := fuzz.NewConsumer(propsData)

		props, cleanup, err := fuzzUtils.CreateProps(ff)
		if err != nil {
			t.Skip()
		}
		defer cleanup()

		it := rpm.New()
		entry, err := it.CreateProposedEntry(context.Background(), version, props)
		if err != nil {
			t.Skip()
		}
		ei, err := types.CreateVersionedEntry(entry)
		if err != nil {
			t.Skip()
		}

		if ok, err := ei.Insertable(); !ok || err != nil {
			t.Errorf("entry created via CreateProposedEntry should be insertable: %v", err)
		}

		if _, err := types.CanonicalizeEntry(context.Background(), ei); err != nil {
			t.Errorf("valid insertable entry should be able to be canonicalized: %v", err)
		}

		_, _ = ei.IndexKeys()
	})
}

func FuzzRpmUnmarshalAndCanonicalize(f *testing.F) {
	f.Fuzz(func(t *testing.T, entryData []byte) {
		initter.Do(fuzzUtils.SetFuzzLogger)

		ff := fuzz.NewConsumer(entryData)

		targetV001 := &models.RpmV001Schema{}

		if err := ff.GenerateStruct(targetV001); err != nil {
			t.Skip()
		}

		targetEntry := &models.Rpm{
			APIVersion: swag.String(APIVERSION),
			Spec:       targetV001,
		}

		ei, err := types.UnmarshalEntry(targetEntry)
		if err != nil {
			t.Skip()
		}

		if _, err := types.CanonicalizeEntry(context.Background(), ei); err != nil {
			t.Skip()
		}
	})
}
