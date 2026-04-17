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
	"errors"
	"testing"

	"github.com/sigstore/rekor/pkg/sharding"
)

func TestRetrieveUUIDFromTree_RejectsUnconfiguredTreeID(t *testing.T) {
	// Set up a minimal API with a single configured shard (tree ID 100).
	api = &API{
		logRanges: sharding.NewLogRangesForTesting(100),
	}

	// Use an unconfigured tree ID (999). The UUID content doesn't matter
	// because the tree ID check should reject the request before any
	// Trillian call is made.
	_, err := retrieveUUIDFromTree(context.Background(), "abcd1234", 999)
	if err == nil {
		t.Fatal("expected error for unconfigured tree ID, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}
