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

package tuf

import (
	"testing"

	"github.com/go-openapi/strfmt"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
)

// Sample test data for benchmarking
var sampleTufData = map[string]any{
	"metadata": map[string]any{
		"content": map[string]any{
			"signed": map[string]any{"_type": "targets", "version": 1},
		},
	},
	"root": map[string]any{
		"content": map[string]any{
			"signed": map[string]any{"_type": "root", "version": 1},
		},
	},
}

// BenchmarkDecodeEntryMapstructure benchmarks the generic mapstructure-based DecodeEntry
func BenchmarkDecodeEntryMapstructure(b *testing.B) {
	for b.Loop() {
		var obj models.TUFV001Schema
		if err := types.DecodeEntry(sampleTufData, &obj); err != nil {
			b.Fatalf("DecodeEntry failed: %v", err)
		}
		if err := obj.Validate(strfmt.Default); err != nil {
			b.Fatalf("Validation failed: %v", err)
		}
	}
}

// BenchmarkDecodeEntryDirect benchmarks the new direct decode method
func BenchmarkDecodeEntryDirect(b *testing.B) {
	for b.Loop() {
		var obj models.TUFV001Schema
		if err := DecodeEntry(sampleTufData, &obj); err != nil {
			b.Fatalf("DecodeEntry direct failed: %v", err)
		}
		if err := obj.Validate(strfmt.Default); err != nil {
			b.Fatalf("Validation failed: %v", err)
		}
	}
}

// BenchmarkDecodeEntryMapstructureMemory benchmarks memory allocation for mapstructure
func BenchmarkDecodeEntryMapstructureMemory(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		var obj models.TUFV001Schema
		if err := types.DecodeEntry(sampleTufData, &obj); err != nil {
			b.Fatalf("DecodeEntry failed: %v", err)
		}
	}
}

// BenchmarkDecodeEntryDirectMemory benchmarks memory allocation for direct method
func BenchmarkDecodeEntryDirectMemory(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		var obj models.TUFV001Schema
		if err := DecodeEntry(sampleTufData, &obj); err != nil {
			b.Fatalf("DecodeEntry direct failed: %v", err)
		}
	}
}
