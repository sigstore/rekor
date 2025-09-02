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
	"github.com/go-openapi/swag"

	fuzzUtils "github.com/sigstore/rekor/pkg/fuzz"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/intoto"
)

var initter sync.Once

func FuzzIntotoCreateProposedEntry(f *testing.F) {
	f.Fuzz(func(t *testing.T, propsData []byte) {
		initter.Do(fuzzUtils.SetFuzzLogger)

		version := "0.0.1"

		ff := fuzz.NewConsumer(propsData)

		props, cleanup, err := fuzzUtils.CreateProps(ff, "intotoV001")
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

		targetV001 := &models.IntotoV001Schema{}

		if err := ff.GenerateStruct(targetV001); err != nil {
			t.Skip()
		}

		targetEntry := &models.Intoto{
			APIVersion: swag.String(APIVERSION),
			Spec:       targetV001,
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

// New: fuzz the direct decoder map fast-path and raw JSON fallbacks
func FuzzIntotoV001DecodeEntryDirectMapAndRaw(f *testing.F) {
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
			m := map[string]any{}
			if b, _ := ff.GetBool(); b {
				m["publicKey"] = toB64(256)
			}
			content := map[string]any{}
			if b, _ := ff.GetBool(); b {
				content["envelope"] = string(append([]byte(`{"payload":"`), []byte(toB64(128))...))
			}
			if b, _ := ff.GetBool(); b {
				content["hash"] = map[string]any{"algorithm": "sha256", "value": "deadbeef"}
			}
			if b, _ := ff.GetBool(); b {
				content["payloadHash"] = map[string]any{"algorithm": "sha256", "value": "cafebabe"}
			}
			m["content"] = content
			input = m
		case 1:
			mdl := &models.IntotoV001Schema{}
			if err := ff.GenerateStruct(mdl); err != nil {
				t.Skip()
			}
			input = mdl
		}
		entry := &V001Entry{}
		if err := DecodeEntry(input, &entry.IntotoObj); err != nil {
			t.Skip()
		}
		_ = entry.IntotoObj.Validate(strfmt.Default)
	})
}
