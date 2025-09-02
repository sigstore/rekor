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
	"encoding/base64"
	"sync"
	"testing"

	fuzz "github.com/AdamKorcz/go-fuzz-headers-1"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	fuzzUtils "github.com/sigstore/rekor/pkg/fuzz"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/cose"
)

var initter sync.Once

func FuzzCoseCreateProposedEntry(f *testing.F) {
	f.Fuzz(func(t *testing.T, propsData []byte) {
		initter.Do(fuzzUtils.SetFuzzLogger)

		version := "0.0.1"

		ff := fuzz.NewConsumer(propsData)

		props, cleanup, err := fuzzUtils.CreateProps(ff, "coseV001")
		if err != nil {
			t.Skip()
		}
		defer func() {
			for _, c := range cleanup {
				c()
			}
		}()

		it := cose.New()
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

func FuzzCoseUnmarshalAndCanonicalize(f *testing.F) {
	f.Fuzz(func(t *testing.T, entryData []byte) {
		initter.Do(fuzzUtils.SetFuzzLogger)

		ff := fuzz.NewConsumer(entryData)

		targetV001 := &models.CoseV001Schema{}

		if err := ff.GenerateStruct(targetV001); err != nil {
			t.Skip()
		}

		targetEntry := &models.Cose{
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
func FuzzCoseDecodeEntryDirectMapAndRaw(f *testing.F) {
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
			// Optional message and publicKey
			if b, _ := ff.GetBool(); b {
				m["message"] = toB64(256)
			}
			if b, _ := ff.GetBool(); b {
				m["publicKey"] = toB64(256)
			}
			// Data block
			if b, _ := ff.GetBool(); b {
				d := map[string]any{}
				if b2, _ := ff.GetBool(); b2 {
					d["payloadHash"] = map[string]any{"algorithm": "sha256", "value": "deadbeef"}
				}
				if b3, _ := ff.GetBool(); b3 {
					d["envelopeHash"] = map[string]any{"algorithm": "sha256", "value": "cafebabe"}
				}
				if b4, _ := ff.GetBool(); b4 {
					d["aad"] = toB64(128)
				}
				m["data"] = d
			}
			input = m
		case 1:
			mdl := &models.CoseV001Schema{}
			if err := ff.GenerateStruct(mdl); err != nil {
				t.Skip()
			}
			input = mdl
		}

		entry := &V001Entry{}
		if err := DecodeEntry(input, &entry.CoseObj); err != nil {
			t.Skip()
		}
		_ = entry.CoseObj.Validate(strfmt.Default)
	})
}
