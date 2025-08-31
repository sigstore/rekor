package helm

import (
	"testing"

	"github.com/go-openapi/strfmt"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
)

// Sample test data for benchmarking - using proper base64 encoded data
var sampleHelmData = map[string]any{
	"publicKey": map[string]any{
		"content": "dGVzdFB1YmxpY0tleQ==", // "testPublicKey" base64 encoded
	},
	"chart": map[string]any{
		"hash": map[string]any{
			"algorithm": "sha256",
			"value":     "abcdef123456",
		},
		"provenance": map[string]any{
			"content": "dGVzdFByb3ZlbmFuY2U=", // "testProvenance" base64 encoded
		},
	},
}

// BenchmarkDecodeEntryMapstructure benchmarks the original mapstructure-based DecodeEntry
func BenchmarkDecodeEntryMapstructure(b *testing.B) {
	for b.Loop() {
		var helmObj models.HelmV001Schema
		err := types.DecodeEntry(sampleHelmData, &helmObj)
		if err != nil {
			b.Fatalf("DecodeEntry failed: %v", err)
		}

		// Validate the result to ensure it's properly decoded
		if err := helmObj.Validate(strfmt.Default); err != nil {
			b.Fatalf("Validation failed: %v", err)
		}
	}
}

// BenchmarkDecodeEntryDirect benchmarks the new direct JSON unmarshaling method
func BenchmarkDecodeEntryDirect(b *testing.B) {
	for b.Loop() {
		entry := &V001Entry{}
		err := DecodeEntry(sampleHelmData, &entry.HelmObj)
		if err != nil {
			b.Fatalf("DecodeEntryDirect failed: %v", err)
		}

		// Validate the result to ensure it's properly decoded
		if err := entry.HelmObj.Validate(strfmt.Default); err != nil {
			b.Fatalf("Validation failed: %v", err)
		}
	}
}

// BenchmarkDecodeEntryMapstructureMemory benchmarks memory allocation for mapstructure
func BenchmarkDecodeEntryMapstructureMemory(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		var helmObj models.HelmV001Schema
		err := types.DecodeEntry(sampleHelmData, &helmObj)
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
		err := DecodeEntry(sampleHelmData, &entry.HelmObj)
		if err != nil {
			b.Fatalf("DecodeEntryDirect failed: %v", err)
		}
	}
}
