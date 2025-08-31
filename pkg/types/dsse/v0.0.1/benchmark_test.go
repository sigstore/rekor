//
// Copyright 2025 The Sigstore Authors.
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
	"testing"

	"github.com/go-openapi/strfmt"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
)

// Sample test data for benchmarking - using proper base64 signatures that match the regex

var sampleDSSEData = map[string]any{
	"proposedContent": map[string]any{
		"envelope":  `{"payload":"dGVzdA==","payloadType":"application/vnd.in-toto+json","signatures":[{"sig":"MEUCIQDGk7qkVHnVahoEn4cLP9DRjxBArABCDEFGHIJKLMNOPQ=="}]}`,
		"verifiers": []string{"dGVzdFZlcmlmaWVyMQ==", "dGVzdFZlcmlmaWVyMg=="},
	},
	"signatures": []map[string]any{
		{
			"signature": "MEUCIQDGk7qkVHnVahoEn4cLP9DRjxBArABCDEFGHIJKLMNOPQ==",
			"verifier":  "dGVzdFZlcmlmaWVyMQ==",
		},
	},
	"envelopeHash": map[string]any{
		"algorithm": "sha256",
		"value":     "abc123",
	},
	"payloadHash": map[string]any{
		"algorithm": "sha256",
		"value":     "def456",
	},
}

// BenchmarkDecodeEntryMapstructure benchmarks the original mapstructure-based DecodeEntry
func BenchmarkDecodeEntryMapstructure(b *testing.B) {
	for b.Loop() {
		var dsseObj models.DSSEV001Schema
		err := types.DecodeEntry(sampleDSSEData, &dsseObj)
		if err != nil {
			b.Fatalf("DecodeEntry failed: %v", err)
		}

		// Validate the result to ensure it's properly decoded
		if err := dsseObj.Validate(strfmt.Default); err != nil {
			b.Fatalf("Validation failed: %v", err)
		}
	}
}

// BenchmarkDecodeEntryDirect benchmarks the new direct JSON unmarshaling method
func BenchmarkDecodeEntryDirect(b *testing.B) {
	for b.Loop() {
		entry := &V001Entry{}
		err := DecodeEntry(sampleDSSEData, &entry.DSSEObj)
		if err != nil {
			b.Fatalf("DecodeEntryDirect failed: %v", err)
		}

		// Validate the result to ensure it's properly decoded
		if err := entry.DSSEObj.Validate(strfmt.Default); err != nil {
			b.Fatalf("Validation failed: %v", err)
		}
	}
}

// BenchmarkDecodeEntryMapstructureMemory benchmarks memory allocation for mapstructure
func BenchmarkDecodeEntryMapstructureMemory(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		var dsseObj models.DSSEV001Schema
		err := types.DecodeEntry(sampleDSSEData, &dsseObj)
		if err != nil {
			b.Fatalf("DecodeEntry failed: %v", err)
		}
	}
}

// BenchmarkDecodeEntryDirectMemory benchmarks memory allocation for direct method
func BenchmarkDecodeEntryDirectMemory(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		entry := &V001Entry{}
		err := DecodeEntry(sampleDSSEData, &entry.DSSEObj)
		if err != nil {
			b.Fatalf("DecodeEntryDirect failed: %v", err)
		}
	}
}
