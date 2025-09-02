//
// Copyright 2023 The Sigstore Authors.
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
	"encoding/base64"
	"sync"
	"testing"

	fuzz "github.com/AdamKorcz/go-fuzz-headers-1"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	fuzzUtils "github.com/sigstore/rekor/pkg/fuzz"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/dsse"
)

var initter sync.Once

func FuzzDSSECreateProposedEntry(f *testing.F) {
	f.Fuzz(func(t *testing.T, propsData []byte) {
		initter.Do(fuzzUtils.SetFuzzLogger)

		ff := fuzz.NewConsumer(propsData)

		props, cleanup, err := fuzzUtils.CreateProps(ff, "dssev001")
		if err != nil {
			t.Skip()
		}
		defer func() {
			for _, c := range cleanup {
				c()
			}
		}()

		it := dsse.New()
		entry, err := it.CreateProposedEntry(context.Background(), APIVERSION, props)
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

func FuzzDSSEUnmarshalAndCanonicalize(f *testing.F) {
	f.Fuzz(func(t *testing.T, entryData []byte) {
		initter.Do(fuzzUtils.SetFuzzLogger)

		ff := fuzz.NewConsumer(entryData)

		targetV001 := &models.DSSEV001Schema{}

		if err := ff.GenerateStruct(targetV001); err != nil {
			t.Skip()
		}

		targetEntry := &models.DSSE{
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

// New: fuzz the direct decoder map fast-path and raw JSON fallbacks, including signature shape variations
func FuzzDSSEDecodeEntryDirectMapAndRaw(f *testing.F) {
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
				pc := map[string]any{"envelope": string(append([]byte(`{"payload":"`), []byte(toB64(128))...))}
				// keep verifiers as []string
				pc["verifiers"] = []string{toB64(64)}
				m["proposedContent"] = pc
			}
			// signatures slice: either []map or []any
			if b, _ := ff.GetBool(); b {
				if b2, _ := ff.GetBool(); b2 {
					m["signatures"] = []map[string]any{{"signature": "MEUCIQ==", "verifier": toB64(32)}}
				} else {
					m["signatures"] = []any{map[string]any{"signature": "MEUCIQ==", "verifier": toB64(32)}}
				}
			}
			// hashes
			if b, _ := ff.GetBool(); b {
				m["envelopeHash"] = map[string]any{"algorithm": "sha256", "value": "deadbeef"}
			}
			if b, _ := ff.GetBool(); b {
				m["payloadHash"] = map[string]any{"algorithm": "sha256", "value": "cafebabe"}
			}
			input = m
		case 1:
			mdl := &models.DSSEV001Schema{}
			if err := ff.GenerateStruct(mdl); err != nil {
				t.Skip()
			}
			input = mdl
		}
		entry := &V001Entry{}
		if err := DecodeEntry(input, &entry.DSSEObj); err != nil {
			t.Skip()
		}
		_ = entry.DSSEObj.Validate(strfmt.Default)
	})
}
