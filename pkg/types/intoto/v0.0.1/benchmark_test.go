package intoto

import (
	"testing"

	"github.com/go-openapi/strfmt"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
)

// Sample test data for benchmarking
var sampleIntotoV001Data = map[string]any{
	"content": map[string]any{
		"envelope": `{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://slsa.dev/provenance/v0.2","subject":[{"name":"test","digest":{"sha256":"abc123"}}],"predicate":{"builder":{"id":"test-builder"}}}`,
		"hash": map[string]any{
			"algorithm": "sha256",
			"value":     "abc123",
		},
		"payloadHash": map[string]any{
			"algorithm": "sha256",
			"value":     "def456",
		},
	},
	"publicKey": "dGVzdFB1YmxpY0tleQ==",
}

// BenchmarkDecodeEntryMapstructure benchmarks the original mapstructure-based DecodeEntry
func BenchmarkDecodeEntryMapstructure(b *testing.B) {
	for b.Loop() {
		var intotoObj models.IntotoV001Schema
		err := types.DecodeEntry(sampleIntotoV001Data, &intotoObj)
		if err != nil {
			b.Fatalf("DecodeEntry failed: %v", err)
		}

		// Validate the result to ensure it's properly decoded
		if err := intotoObj.Validate(strfmt.Default); err != nil {
			b.Fatalf("Validation failed: %v", err)
		}
	}
}

// BenchmarkDecodeEntryDirect benchmarks the new direct JSON unmarshaling method
func BenchmarkDecodeEntryDirect(b *testing.B) {
	for b.Loop() {
		entry := &V001Entry{}
		err := DecodeEntry(sampleIntotoV001Data, &entry.IntotoObj)
		if err != nil {
			b.Fatalf("DecodeEntryDirect failed: %v", err)
		}

		// Validate the result to ensure it's properly decoded
		if err := entry.IntotoObj.Validate(strfmt.Default); err != nil {
			b.Fatalf("Validation failed: %v", err)
		}
	}
}

// BenchmarkDecodeEntryMapstructureMemory benchmarks memory allocation for mapstructure
func BenchmarkDecodeEntryMapstructureMemory(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		var intotoObj models.IntotoV001Schema
		err := types.DecodeEntry(sampleIntotoV001Data, &intotoObj)
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
		err := DecodeEntry(sampleIntotoV001Data, &entry.IntotoObj)
		if err != nil {
			b.Fatalf("DecodeEntryDirect failed: %v", err)
		}
	}
}
