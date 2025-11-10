//
// Copyright 2021 The Sigstore Authors.
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
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/types"
	"github.com/sigstore/rekor/pkg/util"
)

// TrillianClient provides a wrapper around the Trillian client
type TrillianClient struct {
	client trillian.TrillianLogClient
	logID  int64
}

// newTrillianClient creates a TrillianClient with the given Trillian client and log/tree ID.
func newTrillianClient(logClient trillian.TrillianLogClient, logID int64) *TrillianClient {
	return &TrillianClient{
		client: logClient,
		logID:  logID,
	}
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

func (t *TrillianClient) root(ctx context.Context) (types.LogRootV1, error) {
	rqst := &trillian.GetLatestSignedLogRootRequest{
		LogId: t.logID,
	}
	resp, err := t.client.GetLatestSignedLogRoot(ctx, rqst)
	if err != nil {
		return types.LogRootV1{}, err
	}
	return unmarshalLogRoot(resp.SignedLogRoot.LogRoot)
}

func (t *TrillianClient) AddLeaf(ctx context.Context, byteValue []byte) *Response {
	leaf := &trillian.LogLeaf{
		LeafValue: byteValue,
	}
	rqst := &trillian.QueueLeafRequest{
		LogId: t.logID,
		Leaf:  leaf,
	}
	resp, err := t.client.QueueLeaf(ctx, rqst)

	// check for error
	if err != nil || (resp.QueuedLeaf.Status != nil && resp.QueuedLeaf.Status.Code != int32(codes.OK)) {
		return &Response{
			Status:       status.Code(err),
			Err:          err,
			GetAddResult: resp,
		}
	}

	root, err := t.root(ctx)
	if err != nil {
		return &Response{
			Status:       status.Code(err),
			Err:          err,
			GetAddResult: resp,
		}
	}
	v := client.NewLogVerifier(rfc6962.DefaultHasher)
	logClient := client.New(t.logID, t.client, v, root)

	waitForInclusion := func(ctx context.Context, _ []byte) *Response {
		if logClient.MinMergeDelay > 0 {
			select {
			case <-ctx.Done():
				return &Response{
					Status: codes.DeadlineExceeded,
					Err:    ctx.Err(),
				}
			case <-time.After(logClient.MinMergeDelay):
			}
		}
		for {
			root = *logClient.GetRoot()
			if root.TreeSize >= 1 {
				proofResp := t.getProofByHash(ctx, resp.QueuedLeaf.Leaf.MerkleLeafHash)
				// if this call succeeds or returns an error other than "not found", return
				if proofResp.Err == nil || (proofResp.Err != nil && status.Code(proofResp.Err) != codes.NotFound) {
					return proofResp
				}
				// otherwise wait for a root update before trying again
			}

			if _, err := logClient.WaitForRootUpdate(ctx); err != nil {
				return &Response{
					Status: codes.Unknown,
					Err:    err,
				}
			}
		}
	}

	proofResp := waitForInclusion(ctx, resp.QueuedLeaf.Leaf.MerkleLeafHash)
	if proofResp.Err != nil {
		return &Response{
			Status:       status.Code(proofResp.Err),
			Err:          proofResp.Err,
			GetAddResult: resp,
		}
	}

	proofs := proofResp.getProofResult.Proof
	if len(proofs) != 1 {
		err := fmt.Errorf("expected 1 proof from getProofByHash for %v, found %v", hex.EncodeToString(resp.QueuedLeaf.Leaf.MerkleLeafHash), len(proofs))
		return &Response{
			Status:       status.Code(err),
			Err:          err,
			GetAddResult: resp,
		}
	}

	leafIndex := proofs[0].LeafIndex
	// fetch the leaf without re-requesting a proof (since we already have it)
	leafOnlyResp := t.getStandaloneLeaf(ctx, leafIndex, resp.QueuedLeaf.Leaf.MerkleLeafHash, proofs[0], proofResp.getProofResult.SignedLogRoot)
	if leafOnlyResp.Err != nil {
		return &Response{
			Status:       status.Code(leafOnlyResp.Err),
			Err:          leafOnlyResp.Err,
			GetAddResult: resp,
		}
	}

	// Copy this value explicitly because it contains the integrated timestamp
	resp.QueuedLeaf.Leaf = leafOnlyResp.GetLeafAndProofResult.Leaf

	return &Response{
		Status:                codes.OK,
		GetAddResult:          resp,
		GetLeafAndProofResult: leafOnlyResp.GetLeafAndProofResult,
	}
}

func (t *TrillianClient) GetLeafAndProofByHash(ctx context.Context, hash []byte) *Response {
	// get inclusion proof for hash, extract index, then fetch leaf using index
	proofResp := t.getProofByHash(ctx, hash)
	if proofResp.Err != nil {
		return &Response{
			Status: status.Code(proofResp.Err),
			Err:    proofResp.Err,
		}
	}

	proofs := proofResp.getProofResult.Proof
	if len(proofs) != 1 {
		err := fmt.Errorf("expected 1 proof from getProofByHash for %v, found %v", hex.EncodeToString(hash), len(proofs))
		return &Response{
			Status: status.Code(err),
			Err:    err,
		}
	}

	leafIndex := proofs[0].LeafIndex
	// fetch the leaf without re-requesting a proof (since we already have it)
	leafOnlyResp := t.getStandaloneLeaf(ctx, leafIndex, hash, proofs[0], proofResp.getProofResult.SignedLogRoot)
	if leafOnlyResp.Err != nil {
		return &Response{
			Status: status.Code(leafOnlyResp.Err),
			Err:    leafOnlyResp.Err,
		}
	}

	return leafOnlyResp
}

func (t *TrillianClient) GetLeafAndProofByIndex(ctx context.Context, index int64) *Response {
	rootResp := t.GetLatest(ctx, 0)
	if rootResp.Err != nil {
		return &Response{
			Status: status.Code(rootResp.Err),
			Err:    rootResp.Err,
		}
	}

	root, err := unmarshalLogRoot(rootResp.GetLatestResult.SignedLogRoot.LogRoot)
	if err != nil {
		return &Response{
			Status: status.Code(rootResp.Err),
			Err:    rootResp.Err,
		}
	}

	treeSize, err := util.SafeUint64ToInt64(root.TreeSize)
	if err != nil {
		return &Response{
			Status: codes.OutOfRange,
			Err:    status.Error(codes.OutOfRange, err.Error()),
		}
	}

	resp, err := t.client.GetEntryAndProof(ctx,
		&trillian.GetEntryAndProofRequest{
			LogId:     t.logID,
			LeafIndex: index,
			TreeSize:  treeSize,
		})

	if resp != nil && resp.Proof != nil {
		u_index, err := util.SafeInt64ToUint64(index)
		if err != nil {
			return &Response{
				Status: codes.OutOfRange,
				Err:    status.Error(codes.OutOfRange, err.Error()),
			}

		}
		if err := proof.VerifyInclusion(rfc6962.DefaultHasher, u_index, root.TreeSize, resp.GetLeaf().MerkleLeafHash, resp.Proof.Hashes, root.RootHash); err != nil {
			return &Response{
				Status: status.Code(err),
				Err:    err,
			}
		}
		return &Response{
			Status: status.Code(err),
			Err:    err,
			GetLeafAndProofResult: &trillian.GetEntryAndProofResponse{
				Proof:         resp.Proof,
				Leaf:          resp.Leaf,
				SignedLogRoot: rootResp.GetLatestResult.SignedLogRoot,
			},
		}
	}

	return &Response{
		Status: status.Code(err),
		Err:    err,
	}
}

func (t *TrillianClient) GetLatest(ctx context.Context, leafSizeInt int64) *Response {
	resp, err := t.client.GetLatestSignedLogRoot(ctx,
		&trillian.GetLatestSignedLogRootRequest{
			LogId:         t.logID,
			FirstTreeSize: leafSizeInt,
		})

	return &Response{
		Status:          status.Code(err),
		Err:             err,
		GetLatestResult: resp,
	}
}

func (t *TrillianClient) GetConsistencyProof(ctx context.Context, firstSize, lastSize int64) *Response {
	resp, err := t.client.GetConsistencyProof(ctx,
		&trillian.GetConsistencyProofRequest{
			LogId:          t.logID,
			FirstTreeSize:  firstSize,
			SecondTreeSize: lastSize,
		})

	return &Response{
		Status:                    status.Code(err),
		Err:                       err,
		GetConsistencyProofResult: resp,
	}
}

func (t *TrillianClient) getProofByHash(ctx context.Context, hashValue []byte) *Response {
	rootResp := t.GetLatest(ctx, 0)
	if rootResp.Err != nil {
		return &Response{
			Status: status.Code(rootResp.Err),
			Err:    rootResp.Err,
		}
	}
	root, err := unmarshalLogRoot(rootResp.GetLatestResult.SignedLogRoot.LogRoot)
	if err != nil {
		return &Response{
			Status: status.Code(rootResp.Err),
			Err:    rootResp.Err,
		}
	}

	// issue 1308: if the tree is empty, there's no way we can return a proof
	if root.TreeSize == 0 {
		return &Response{
			Status: codes.NotFound,
			Err:    status.Error(codes.NotFound, "tree is empty"),
		}
	}

	treeSize, err := util.SafeUint64ToInt64(root.TreeSize)
	if err != nil {
		return &Response{
			Status: codes.OutOfRange,
			Err:    status.Error(codes.OutOfRange, err.Error()),
		}
	}

	resp, err := t.client.GetInclusionProofByHash(ctx,
		&trillian.GetInclusionProofByHashRequest{
			LogId:    t.logID,
			LeafHash: hashValue,
			TreeSize: treeSize,
		})

	if resp != nil {
		v := client.NewLogVerifier(rfc6962.DefaultHasher)
		for _, proof := range resp.Proof {
			if err := v.VerifyInclusionByHash(&root, hashValue, proof); err != nil {
				return &Response{
					Status: status.Code(err),
					Err:    err,
				}
			}
		}
		// Return an inclusion proof response with the requested
		return &Response{
			Status: status.Code(err),
			Err:    err,
			getProofResult: &trillian.GetInclusionProofByHashResponse{
				Proof:         resp.Proof,
				SignedLogRoot: rootResp.GetLatestResult.SignedLogRoot,
			},
		}
	}

	return &Response{
		Status: status.Code(err),
		Err:    err,
	}
}

// GetLeavesByRange fetches leaves from startIndex (inclusive) up to count leaves without proofs.
func (t *TrillianClient) GetLeavesByRange(ctx context.Context, startIndex, count int64) *Response {
	resp, err := t.client.GetLeavesByRange(ctx, &trillian.GetLeavesByRangeRequest{
		LogId:      t.logID,
		StartIndex: startIndex,
		Count:      count,
	})
	return &Response{
		Status:                 status.Code(err),
		Err:                    err,
		GetLeavesByRangeResult: resp,
	}
}

// GetLeafWithoutProof is a convenience wrapper for fetching a single leaf by index without proofs.
func (t *TrillianClient) GetLeafWithoutProof(ctx context.Context, index int64) *Response {
	return t.GetLeavesByRange(ctx, index, 1)
}

// getStandaloneLeaf gets just the leaf, returns it in GetLeafAndProof result for easier reuse
func (t *TrillianClient) getStandaloneLeaf(ctx context.Context, index int64, hash []byte, proof *trillian.Proof, signedRoot *trillian.SignedLogRoot) *Response {
	leafOnlyResp := t.GetLeafWithoutProof(ctx, index)
	if leafOnlyResp.Err != nil {
		return &Response{
			Status: status.Code(leafOnlyResp.Err),
			Err:    leafOnlyResp.Err,
		}
	}

	if leafOnlyResp.GetLeavesByRangeResult == nil || len(leafOnlyResp.GetLeavesByRangeResult.Leaves) == 0 {
		err := fmt.Errorf("no leaf returned for index %d", index)
		return &Response{
			Status: codes.NotFound,
			Err:    err,
		}
	}
	// shouldn't happen since we're using a log mode that prevents duplicates
	if len(leafOnlyResp.GetLeavesByRangeResult.Leaves) != 1 {
		err := fmt.Errorf("multiple leaves returned for index %d", index)
		return &Response{
			Status: codes.FailedPrecondition,
			Err:    err,
		}
	}
	leaf := leafOnlyResp.GetLeavesByRangeResult.Leaves[0]

	if !bytes.Equal(leaf.MerkleLeafHash, hash) {
		// extremely unlikely but this means the index in the proof doesn't match the content stored in the index
		err := fmt.Errorf("leaf hash mismatch: expected %v, got %v", hex.EncodeToString(hash), hex.EncodeToString(leaf.MerkleLeafHash))
		return &Response{
			Status: status.Code(err),
			Err:    err,
		}
	}

	return &Response{
		Status: codes.OK,
		GetLeafAndProofResult: &trillian.GetEntryAndProofResponse{
			Proof:         proof,
			Leaf:          leaf,
			SignedLogRoot: signedRoot,
		},
	}
}
