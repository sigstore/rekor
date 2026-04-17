//
// Copyright 2026 The Sigstore Authors.
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
