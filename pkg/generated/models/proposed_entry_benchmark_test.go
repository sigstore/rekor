// Copyright 2026 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package models

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/go-openapi/runtime"
)

// Real ProposedEntry fixtures constructed from checked-in test inputs:
//
//	dsse.json         — wraps tests/intoto_dsse.json (a real signed DSSE
//	                    envelope) as a ProposedEntry with the matching
//	                    verifier from tests/intoto_dsse.pem.
//	hashedrekord.json — real ECDSA signature + PEM from
//	                    pkg/pki/x509/testdata/ over hello_world.txt.
//	intoto.json       — same DSSE envelope wrapped in intoto v0.0.2 shape
//	                    with real envelope hash + PEM.
//
//go:embed testdata/dsse.json
var realDSSEBody []byte

//go:embed testdata/hashedrekord.json
var realHashedRekordBody []byte

//go:embed testdata/intoto.json
var realIntotoBody []byte

var benchmarkProposedEntrySink ProposedEntry

func BenchmarkUnmarshalProposedEntry(b *testing.B) {
	cases := []struct {
		name    string
		body    []byte
		wantErr bool
	}{
		{"dsse", realDSSEBody, false},
		{"hashedrekord", realHashedRekordBody, false},
		{"intoto", realIntotoBody, false},
		{"unknown_kind", unknownKindBody(b), true},
	}

	consumer := runtime.JSONConsumer()

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(tc.body)))
			for b.Loop() {
				pe, err := UnmarshalProposedEntry(bytes.NewReader(tc.body), consumer)
				if tc.wantErr {
					if err == nil {
						b.Fatalf("expected error, got %#v", pe)
					}
					continue
				}
				if err != nil {
					b.Fatalf("UnmarshalProposedEntry failed: %v", err)
				}
				benchmarkProposedEntrySink = pe
			}
		})
	}
}

func unknownKindBody(b *testing.B) []byte {
	b.Helper()
	body, err := json.Marshal(map[string]any{
		"kind":       "not-a-real-kind",
		"apiVersion": "0.0.1",
		"spec":       map[string]any{},
	})
	if err != nil {
		b.Fatal(err)
	}
	return body
}
