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
)

// simpleTrillianClient is a stateless, per-RPC wrapper around the Trillian gRPC
// client. It fetches a fresh root on every operation that requires one, with no
// background goroutines or cached state.
type simpleTrillianClient struct {
	client trillian.TrillianLogClient
	logID  int64
}

// newSimpleTrillianClient creates a simpleTrillianClient.
func newSimpleTrillianClient(logClient trillian.TrillianLogClient, logID int64) *simpleTrillianClient {
	return &simpleTrillianClient{
		client: logClient,
		logID:  logID,
	}
}

func (t *simpleTrillianClient) root(ctx context.Context) (types.LogRootV1, error) {
	rqst := &trillian.GetLatestSignedLogRootRequest{
		LogId: t.logID,
	}
	resp, err := t.client.GetLatestSignedLogRoot(ctx, rqst)
	if err != nil {
		return types.LogRootV1{}, err
	}
	if resp == nil || resp.SignedLogRoot == nil {
		return types.LogRootV1{}, fmt.Errorf("nil signed log root in response")
	}
	return unmarshalLogRoot(resp.SignedLogRoot.LogRoot)
}

func (t *simpleTrillianClient) AddLeaf(ctx context.Context, byteValue []byte) *Response {
	leaf := &trillian.LogLeaf{
		LeafValue: byteValue,
	}
	rqst := &trillian.QueueLeafRequest{
		LogId: t.logID,
		Leaf:  leaf,
	}
	resp, err := t.client.QueueLeaf(ctx, rqst)
	if err != nil {
		return &Response{
			Status:       status.Code(err),
			Err:          err,
			GetAddResult: resp,
		}
	}
	if resp == nil || resp.QueuedLeaf == nil || resp.QueuedLeaf.Leaf == nil {
		return &Response{
			Status: codes.Internal,
			Err:    fmt.Errorf("unexpected nil in QueueLeaf response"),
		}
	}
	// Non-OK insertion status (e.g. ALREADY_EXISTS) is not a gRPC error.
	// Return Status: OK with the response so callers can inspect QueuedLeaf.Status
	// to determine the insertion-level outcome (e.g. HTTP 409 for duplicates).
	if resp.QueuedLeaf.Status != nil && resp.QueuedLeaf.Status.Code != int32(codes.OK) {
		return &Response{
			Status:       codes.OK,
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

	waitForInclusion := func(ctx context.Context) *Response {
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
				if proofResp.Err == nil || (proofResp.Err != nil && status.Code(proofResp.Err) != codes.NotFound) {
					return proofResp
				}
			}

			if _, err := logClient.WaitForRootUpdate(ctx); err != nil {
				return &Response{
					Status: codes.Unknown,
					Err:    err,
				}
			}
		}
	}

	proofResp := waitForInclusion(ctx)
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
	leafOnlyResp := t.getStandaloneLeaf(ctx, leafIndex, resp.QueuedLeaf.Leaf.MerkleLeafHash, proofs[0], proofResp.getProofResult.SignedLogRoot)
	if leafOnlyResp.Err != nil {
		return &Response{
			Status:       status.Code(leafOnlyResp.Err),
			Err:          leafOnlyResp.Err,
			GetAddResult: resp,
		}
	}

	resp.QueuedLeaf.Leaf = leafOnlyResp.GetLeafAndProofResult.Leaf

	return &Response{
		Status:                codes.OK,
		GetAddResult:          resp,
		GetLeafAndProofResult: leafOnlyResp.GetLeafAndProofResult,
	}
}

func (t *simpleTrillianClient) GetLeafAndProofByHash(ctx context.Context, hash []byte) *Response {
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
	leafOnlyResp := t.getStandaloneLeaf(ctx, leafIndex, hash, proofs[0], proofResp.getProofResult.SignedLogRoot)
	if leafOnlyResp.Err != nil {
		return &Response{
			Status: status.Code(leafOnlyResp.Err),
			Err:    leafOnlyResp.Err,
		}
	}

	return leafOnlyResp
}

func (t *simpleTrillianClient) GetLeafAndProofByIndex(ctx context.Context, index int64) *Response {
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
			Status: status.Code(err),
			Err:    err,
		}
	}

	resp, err := t.client.GetEntryAndProof(ctx,
		&trillian.GetEntryAndProofRequest{
			LogId:     t.logID,
			LeafIndex: index,
			TreeSize:  int64(root.TreeSize),
		})

	if resp != nil && resp.Proof != nil {
		if err := proof.VerifyInclusion(rfc6962.DefaultHasher, uint64(index), root.TreeSize, resp.GetLeaf().MerkleLeafHash, resp.Proof.Hashes, root.RootHash); err != nil {
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

func (t *simpleTrillianClient) GetLatest(ctx context.Context, leafSizeInt int64) *Response {
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

func (t *simpleTrillianClient) GetConsistencyProof(ctx context.Context, firstSize, lastSize int64) *Response {
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

func (t *simpleTrillianClient) getProofByHash(ctx context.Context, hashValue []byte) *Response {
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
			Status: status.Code(err),
			Err:    err,
		}
	}

	if root.TreeSize == 0 {
		return &Response{
			Status: codes.NotFound,
			Err:    status.Error(codes.NotFound, "tree is empty"),
		}
	}

	resp, err := t.client.GetInclusionProofByHash(ctx,
		&trillian.GetInclusionProofByHashRequest{
			LogId:    t.logID,
			LeafHash: hashValue,
			TreeSize: int64(root.TreeSize),
		})

	if resp != nil {
		v := client.NewLogVerifier(rfc6962.DefaultHasher)
		for _, p := range resp.Proof {
			if err := v.VerifyInclusionByHash(&root, hashValue, p); err != nil {
				return &Response{
					Status: status.Code(err),
					Err:    err,
				}
			}
		}
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
func (t *simpleTrillianClient) GetLeavesByRange(ctx context.Context, startIndex, count int64) *Response {
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
func (t *simpleTrillianClient) GetLeafWithoutProof(ctx context.Context, index int64) *Response {
	return t.GetLeavesByRange(ctx, index, 1)
}

// Close is a no-op for the simple client (no background goroutines).
func (t *simpleTrillianClient) Close() {}

// getStandaloneLeaf gets just the leaf, returns it in GetLeafAndProof result for easier reuse.
func (t *simpleTrillianClient) getStandaloneLeaf(ctx context.Context, index int64, hash []byte, p *trillian.Proof, signedRoot *trillian.SignedLogRoot) *Response {
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
	if len(leafOnlyResp.GetLeavesByRangeResult.Leaves) != 1 {
		err := fmt.Errorf("multiple leaves returned for index %d", index)
		return &Response{
			Status: codes.FailedPrecondition,
			Err:    err,
		}
	}
	leaf := leafOnlyResp.GetLeavesByRangeResult.Leaves[0]

	if !bytes.Equal(leaf.MerkleLeafHash, hash) {
		err := fmt.Errorf("leaf hash mismatch: expected %v, got %v", hex.EncodeToString(hash), hex.EncodeToString(leaf.MerkleLeafHash))
		return &Response{
			Status: status.Code(err),
			Err:    err,
		}
	}

	return &Response{
		Status: codes.OK,
		GetLeafAndProofResult: &trillian.GetEntryAndProofResponse{
			Proof:         p,
			Leaf:          leaf,
			SignedLogRoot: signedRoot,
		},
	}
}
