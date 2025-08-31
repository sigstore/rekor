package hashedrekord

import (
	"testing"

	"github.com/go-openapi/strfmt"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
)

// Sample test data for benchmarking
var sampleHashedRekordData = map[string]any{
	"signature": map[string]any{
		"content": "dGVzdFNpZ25hdHVyZQ==",
		"publicKey": map[string]any{
			"content": "dGVzdFB1YmxpY0tleQ==",
		},
	},
	"data": map[string]any{
		"hash": map[string]any{
			"algorithm": "sha256",
			"value":     "abc123def456",
		},
	},
}

// BenchmarkDecodeEntryMapstructure benchmarks the original mapstructure-based DecodeEntry
func BenchmarkDecodeEntryMapstructure(b *testing.B) {
	for b.Loop() {
		var hashedRekordObj models.HashedrekordV001Schema
		err := types.DecodeEntry(sampleHashedRekordData, &hashedRekordObj)
		if err != nil {
			b.Fatalf("DecodeEntry failed: %v", err)
		}

		// Validate the result to ensure it's properly decoded
		if err := hashedRekordObj.Validate(strfmt.Default); err != nil {
			b.Fatalf("Validation failed: %v", err)
		}
	}
}

// BenchmarkDecodeEntryDirect benchmarks the new direct JSON unmarshaling method
func BenchmarkDecodeEntryDirect(b *testing.B) {
	for b.Loop() {
		entry := &V001Entry{}
		err := DecodeEntry(sampleHashedRekordData, &entry.HashedRekordObj)
		if err != nil {
			b.Fatalf("DecodeEntryDirect failed: %v", err)
		}

		// Validate the result to ensure it's properly decoded
		if err := entry.HashedRekordObj.Validate(strfmt.Default); err != nil {
			b.Fatalf("Validation failed: %v", err)
		}
	}
}

// BenchmarkDecodeEntryMapstructureMemory benchmarks memory allocation for mapstructure
func BenchmarkDecodeEntryMapstructureMemory(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		var hashedRekordObj models.HashedrekordV001Schema
		err := types.DecodeEntry(sampleHashedRekordData, &hashedRekordObj)
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
		err := DecodeEntry(sampleHashedRekordData, &entry.HashedRekordObj)
		if err != nil {
			b.Fatalf("DecodeEntryDirect failed: %v", err)
		}
	}
}
