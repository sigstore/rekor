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
	"encoding/base64"
	"sync"
	"testing"

	fuzz "github.com/AdamKorcz/go-fuzz-headers-1"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag/conv"

	fuzzUtils "github.com/sigstore/rekor/pkg/fuzz"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/intoto"
)

var initter sync.Once

func FuzzIntotoCreateProposedEntry(f *testing.F) {
	f.Fuzz(func(t *testing.T, propsData []byte) {
		initter.Do(fuzzUtils.SetFuzzLogger)

		version := "0.0.2"

		ff := fuzz.NewConsumer(propsData)

		props, cleanup, err := fuzzUtils.CreateProps(ff, "intotoV002")
		if err != nil {
			t.Skip()
		}
		defer func() {
			for _, c := range cleanup {
				c()
			}
		}()

		it := intoto.New()
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

func FuzzIntotoUnmarshalAndCanonicalize(f *testing.F) {
	f.Fuzz(func(t *testing.T, entryData []byte) {
		initter.Do(fuzzUtils.SetFuzzLogger)

		ff := fuzz.NewConsumer(entryData)

		targetV002 := &models.IntotoV002Schema{}

		if err := ff.GenerateStruct(targetV002); err != nil {
			t.Skip()
		}

		targetEntry := &models.Intoto{
			APIVersion: conv.Pointer(APIVERSION),
			Spec:       targetV002,
		}

		ei, err := types.UnmarshalEntry(targetEntry)
		if err != nil {
			t.Skip()
		}

		if _, err := types.CanonicalizeEntry(context.Background(), ei); err != nil {
			t.Errorf("error canonicalizing unmarshalled entry: %v", err)
		}
	})
}

// New: fuzz the direct decoder map fast-path and typed-model inputs
func FuzzIntotoDecodeEntryDirectMapAndRaw(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		initter.Do(fuzzUtils.SetFuzzLogger)
		ff := fuzz.NewConsumer(data)
		choice, _ := ff.GetInt()
		choice %= 2
		toB64 := func(limit int) string {
			b, _ := ff.GetBytes()
			if len(b) > limit {
				b = b[:limit]
			}
			return base64.StdEncoding.EncodeToString(b)
		}

		var input any
		switch choice {
		case 0:
			// Construct a minimal map resembling the schema
			m := map[string]any{}
			content := map[string]any{}
			env := map[string]any{}
			if b, _ := ff.GetBool(); b {
				env["payloadType"] = "application/vnd.in-toto+json"
				env["payload"] = toB64(512)
			}
			if b, _ := ff.GetBool(); b {
				env["signatures"] = []any{map[string]any{"keyid": "k", "sig": toB64(128), "publicKey": toB64(256)}}
			}
			if len(env) > 0 {
				content["envelope"] = env
			}
			if b, _ := ff.GetBool(); b {
				content["hash"] = map[string]any{"algorithm": "sha256", "value": "deadbeef"}
			}
			if b, _ := ff.GetBool(); b {
				content["payloadHash"] = map[string]any{"algorithm": "sha256", "value": "deadbeef"}
			}
			if len(content) > 0 {
				m["content"] = content
			}
			input = m
		case 1:
			mdl := &models.IntotoV002Schema{}
			if err := ff.GenerateStruct(mdl); err != nil {
				t.Skip()
			}
			input = mdl
		}
		entry := &V002Entry{}
		if err := DecodeEntry(input, &entry.IntotoObj); err != nil {
			t.Skip()
		}
		_ = entry.IntotoObj.Validate(strfmt.Default)
	})
}
