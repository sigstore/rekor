package jar

import (
	"testing"

	"github.com/go-openapi/strfmt"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
)

// Sample test data for benchmarking - using proper base64 encoded data
var sampleJARData = map[string]any{
	"signature": map[string]any{
		"content": "dGVzdFNpZ25hdHVyZQ==", // "testSignature" base64 encoded
		"publicKey": map[string]any{
			"content": "dGVzdFB1YmxpY0tleQ==", // "testPublicKey" base64 encoded
		},
	},
	"archive": map[string]any{
		"hash": map[string]any{
			"algorithm": "sha256",
			"value":     "abcdef123456",
		},
		"content": "dGVzdEFyY2hpdmU=", // "testArchive" base64 encoded
	},
}

// BenchmarkDecodeEntryMapstructure benchmarks the original mapstructure-based DecodeEntry
func BenchmarkDecodeEntryMapstructure(b *testing.B) {
	for b.Loop() {
		var jarObj models.JarV001Schema
		err := types.DecodeEntry(sampleJARData, &jarObj)
		if err != nil {
			b.Fatalf("DecodeEntry failed: %v", err)
		}

		// Validate the result to ensure it's properly decoded
		if err := jarObj.Validate(strfmt.Default); err != nil {
			b.Fatalf("Validation failed: %v", err)
		}
	}
}

// BenchmarkDecodeEntryDirect benchmarks the new direct JSON unmarshaling method
func BenchmarkDecodeEntryDirect(b *testing.B) {
	for b.Loop() {
		entry := &V001Entry{}
		err := DecodeEntry(sampleJARData, &entry.JARModel)
		if err != nil {
			b.Fatalf("DecodeEntryDirect failed: %v", err)
		}

		// Validate the result to ensure it's properly decoded
		if err := entry.JARModel.Validate(strfmt.Default); err != nil {
			b.Fatalf("Validation failed: %v", err)
		}
	}
}

// BenchmarkDecodeEntryMapstructureMemory benchmarks memory allocation for mapstructure
func BenchmarkDecodeEntryMapstructureMemory(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		var jarObj models.JarV001Schema
		err := types.DecodeEntry(sampleJARData, &jarObj)
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
		err := DecodeEntry(sampleJARData, &entry.JARModel)
		if err != nil {
			b.Fatalf("DecodeEntryDirect failed: %v", err)
		}
	}
}
