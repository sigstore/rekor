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

package trillianclient

import (
	"context"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"google.golang.org/grpc/codes"
)

// TrillianClientInterface defines the public API for interacting with a Trillian log.
// Two implementations exist:
//   - simpleTrillianClient: stateless, per-RPC client (default)
//   - TrillianClient: cached STH client with background root updates (experimental, opt-in via CacheSTH)
type TrillianClientInterface interface {
	AddLeaf(ctx context.Context, byteValue []byte) *Response
	GetLatest(ctx context.Context, firstSize int64) *Response
	GetLeafAndProofByHash(ctx context.Context, hash []byte) *Response
	GetLeafAndProofByIndex(ctx context.Context, index int64) *Response
	GetConsistencyProof(ctx context.Context, firstSize, lastSize int64) *Response
	GetLeavesByRange(ctx context.Context, startIndex, count int64) *Response
	GetLeafWithoutProof(ctx context.Context, index int64) *Response
	Close()
}

// Response includes a status code, an optional error message, and one of the results based on the API call
type Response struct {
	// Status is the status code of the response
	Status codes.Code
	// Error contains an error on request or client failure
	Err error
	// GetAddResult contains the response from queueing a leaf in Trillian
	GetAddResult *trillian.QueueLeafResponse
	// GetLeafAndProofResult contains the response for fetching an inclusion proof and leaf
	GetLeafAndProofResult *trillian.GetEntryAndProofResponse
	// GetLatestResult contains the response for the latest checkpoint
	GetLatestResult *trillian.GetLatestSignedLogRootResponse
	// GetConsistencyProofResult contains the response for a consistency proof between two log sizes
	GetConsistencyProofResult *trillian.GetConsistencyProofResponse
	// GetLeavesByRangeResult contains the response for fetching a leaf without an inclusion proof
	GetLeavesByRangeResult *trillian.GetLeavesByRangeResponse
	// getProofResult contains the response for an inclusion proof fetched by leaf hash
	getProofResult *trillian.GetInclusionProofByHashResponse
}

func unmarshalLogRoot(logRoot []byte) (types.LogRootV1, error) {
	var root types.LogRootV1
	if err := root.UnmarshalBinary(logRoot); err != nil {
		return types.LogRootV1{}, err
	}
	return root, nil
}
