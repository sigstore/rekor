package rfc3161

import (
	"testing"

	"github.com/go-openapi/strfmt"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
)

// Sample test data for benchmarking - using proper base64 encoded data
var sampleRFC3161Data = map[string]any{
	"tsr": map[string]any{
		"content": "dGVzdFRTUg==", // "testTSR" base64 encoded
	},
}

// BenchmarkDecodeEntryMapstructure benchmarks the original mapstructure-based DecodeEntry
func BenchmarkDecodeEntryMapstructure(b *testing.B) {
	for b.Loop() {
		var rfc3161Obj models.Rfc3161V001Schema
		err := types.DecodeEntry(sampleRFC3161Data, &rfc3161Obj)
		if err != nil {
			b.Fatalf("DecodeEntry failed: %v", err)
		}

		// Validate the result to ensure it's properly decoded
		if err := rfc3161Obj.Validate(strfmt.Default); err != nil {
			b.Fatalf("Validation failed: %v", err)
		}
	}
}

// BenchmarkDecodeEntryDirect benchmarks the new direct JSON unmarshaling method
func BenchmarkDecodeEntryDirect(b *testing.B) {
	for b.Loop() {
		entry := &V001Entry{}
		err := DecodeEntry(sampleRFC3161Data, &entry.Rfc3161Obj)
		if err != nil {
			b.Fatalf("DecodeEntryDirect failed: %v", err)
		}

		// Validate the result to ensure it's properly decoded
		if err := entry.Rfc3161Obj.Validate(strfmt.Default); err != nil {
			b.Fatalf("Validation failed: %v", err)
		}
	}
}

// BenchmarkDecodeEntryMapstructureMemory benchmarks memory allocation for mapstructure
func BenchmarkDecodeEntryMapstructureMemory(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		var rfc3161Obj models.Rfc3161V001Schema
		err := types.DecodeEntry(sampleRFC3161Data, &rfc3161Obj)
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
		err := DecodeEntry(sampleRFC3161Data, &entry.Rfc3161Obj)
		if err != nil {
			b.Fatalf("DecodeEntryDirect failed: %v", err)
		}
	}
}
