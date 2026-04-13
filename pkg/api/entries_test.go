package api

import (
	"context"
	"testing"

	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/signer"
)

// TestRetrieveUUIDFromTree_UnconfiguredTreeID tests that retrieveUUIDFromTree returns ErrNotFound when the tree ID is not in the configured shard set.
// This ensures that the API correctly rejects requests for tree IDs that are not configured, preventing unnecessary calls to the Trillian client manager and backend.
func TestRetrieveUUIDFromTree_UnconfiguredTreeID(t *testing.T) {
	ranges, err := sharding.NewLogRanges(context.Background(), "", 1, signer.SigningConfig{SigningSchemeOrKeyPath: "memory"})
	if err != nil {
		t.Fatalf("Failed to create LogRanges: %v", err)
	}

	api = &API{
		logRanges: ranges,
		// explicitly nil. if validation fails, using this manager will panic.
		trillianClientManager: nil,
	}

	validUUID := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	_, err = retrieveUUIDFromTree(context.Background(), validUUID, 999)

	if err != ErrNotFound {
		t.Errorf("Expected ErrNotFound, got: %v", err)
	}
}
