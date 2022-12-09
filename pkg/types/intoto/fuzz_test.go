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

package intoto

import (
	"context"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	"github.com/sigstore/rekor/pkg/types"
)

func FuzzIntotoCreateProposedEntry(f *testing.F) {
	f.Fuzz(func(t *testing.T, version string, propsData []byte) {
		ff := fuzz.NewConsumer(propsData)
		props := types.ArtifactProperties{}
		ff.GenerateStruct(&props)
		it := New()
		entry, err := it.CreateProposedEntry(context.Background(), version, props)
		if err != nil {
			t.Skip()
		}
		_, err = it.UnmarshalEntry(entry)
		if err != nil {
			t.Skip()
		}
	})
}
