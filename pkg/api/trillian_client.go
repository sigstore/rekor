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

package api

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/types"
)

type TrillianClient struct {
	client  trillian.TrillianLogClient
	ranges  sharding.LogRanges
	logID   int64
	context context.Context
}

func NewTrillianClient(ctx context.Context) TrillianClient {
	return TrillianClient{
		client:  api.logClient,
		ranges:  api.logRanges,
		logID:   api.logID,
		context: ctx,
	}
}

func NewTrillianClientFromTreeID(ctx context.Context, tid int64) TrillianClient {
	return TrillianClient{
		client:  api.logClient,
		logID:   tid,
		context: ctx,
	}
}

type Response struct {
	status                    codes.Code
	err                       error
	getAddResult              *trillian.QueueLeafResponse
	getProofResult            *trillian.GetInclusionProofByHashResponse
	getLeafAndProofResult     *trillian.GetEntryAndProofResponse
	getLatestResult           *trillian.GetLatestSignedLogRootResponse
	getConsistencyProofResult *trillian.GetConsistencyProofResponse
}

func unmarshalLogRoot(logRoot []byte) (types.LogRootV1, error) {
	var root types.LogRootV1
	if err := root.UnmarshalBinary(logRoot); err != nil {
		return types.LogRootV1{}, err
	}
	return root, nil
}

func (t *TrillianClient) root() (types.LogRootV1, error) {
	rqst := &trillian.GetLatestSignedLogRootRequest{
		LogId: t.logID,
	}
	resp, err := t.client.GetLatestSignedLogRoot(t.context, rqst)
	if err != nil {
		return types.LogRootV1{}, err
	}
	return unmarshalLogRoot(resp.SignedLogRoot.LogRoot)
}

func (t *TrillianClient) addLeaf(byteValue []byte) *Response {
	leaf := &trillian.LogLeaf{
		LeafValue: byteValue,
	}
	rqst := &trillian.QueueLeafRequest{
		LogId: t.logID,
		Leaf:  leaf,
	}
	resp, err := t.client.QueueLeaf(t.context, rqst)

	// check for error
	if err != nil || (resp.QueuedLeaf.Status != nil && resp.QueuedLeaf.Status.Code != int32(codes.OK)) {
		return &Response{
			status:       status.Code(err),
			err:          err,
			getAddResult: resp,
		}
	}

	root, err := t.root()
	if err != nil {
		return &Response{
			status:       status.Code(err),
			err:          err,
			getAddResult: resp,
		}
	}
	v := client.NewLogVerifier(rfc6962.DefaultHasher)
	logClient := client.New(t.logID, t.client, v, root)

	waitForInclusion := func(ctx context.Context, leafHash []byte) *Response {
		if logClient.MinMergeDelay > 0 {
			select {
			case <-ctx.Done():
				return &Response{
					status: codes.DeadlineExceeded,
					err:    ctx.Err(),
				}
			case <-time.After(logClient.MinMergeDelay):
			}
		}
		for {
			root = *logClient.GetRoot()
			if root.TreeSize >= 1 {
				proofResp := t.getProofByHash(resp.QueuedLeaf.Leaf.MerkleLeafHash)
				// if this call succeeds or returns an error other than "not found", return
				if proofResp.err == nil || (proofResp.err != nil && status.Code(proofResp.err) != codes.NotFound) {
					return proofResp
				}
				// otherwise wait for a root update before trying again
			}

			if _, err := logClient.WaitForRootUpdate(ctx); err != nil {
				return &Response{
					status: codes.Unknown,
					err:    err,
				}
			}
		}
	}

	proofResp := waitForInclusion(t.context, resp.QueuedLeaf.Leaf.MerkleLeafHash)
	if proofResp.err != nil {
		return &Response{
			status:       status.Code(proofResp.err),
			err:          proofResp.err,
			getAddResult: resp,
		}
	}

	proofs := proofResp.getProofResult.Proof
	if len(proofs) != 1 {
		err := fmt.Errorf("expected 1 proof from getProofByHash for %v, found %v", hex.EncodeToString(resp.QueuedLeaf.Leaf.MerkleLeafHash), len(proofs))
		return &Response{
			status:       status.Code(err),
			err:          err,
			getAddResult: resp,
		}
	}

	leafIndex := proofs[0].LeafIndex
	leafResp := t.getLeafAndProofByIndex(leafIndex)
	if leafResp.err != nil {
		return &Response{
			status:       status.Code(leafResp.err),
			err:          leafResp.err,
			getAddResult: resp,
		}
	}

	// overwrite queued leaf that doesn't have index set
	resp.QueuedLeaf.Leaf = leafResp.getLeafAndProofResult.Leaf

	return &Response{
		status:       status.Code(err),
		err:          err,
		getAddResult: resp,
		// include getLeafAndProofResult for inclusion proof
		getLeafAndProofResult: leafResp.getLeafAndProofResult,
	}
}

func (t *TrillianClient) getLeafAndProofByHash(hash []byte) *Response {
	// get inclusion proof for hash, extract index, then fetch leaf using index
	proofResp := t.getProofByHash(hash)
	if proofResp.err != nil {
		return &Response{
			status: status.Code(proofResp.err),
			err:    proofResp.err,
		}
	}

	proofs := proofResp.getProofResult.Proof
	if len(proofs) != 1 {
		err := fmt.Errorf("expected 1 proof from getProofByHash for %v, found %v", hex.EncodeToString(hash), len(proofs))
		return &Response{
			status: status.Code(err),
			err:    err,
		}
	}

	return t.getLeafAndProofByIndex(proofs[0].LeafIndex)
}

func (t *TrillianClient) getLeafAndProofByIndex(index int64) *Response {
	ctx, cancel := context.WithTimeout(t.context, 20*time.Second)
	defer cancel()

	rootResp := t.getLatest(0)
	if rootResp.err != nil {
		return &Response{
			status: status.Code(rootResp.err),
			err:    rootResp.err,
		}
	}

	root, err := unmarshalLogRoot(rootResp.getLatestResult.SignedLogRoot.LogRoot)
	if err != nil {
		return &Response{
			status: status.Code(rootResp.err),
			err:    rootResp.err,
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
				status: status.Code(err),
				err:    err,
			}
		}
		return &Response{
			status: status.Code(err),
			err:    err,
			getLeafAndProofResult: &trillian.GetEntryAndProofResponse{
				Proof:         resp.Proof,
				Leaf:          resp.Leaf,
				SignedLogRoot: rootResp.getLatestResult.SignedLogRoot,
			},
		}
	}

	return &Response{
		status: status.Code(err),
		err:    err,
	}
}

func (t *TrillianClient) getProofByHash(hashValue []byte) *Response {
	ctx, cancel := context.WithTimeout(t.context, 20*time.Second)
	defer cancel()

	rootResp := t.getLatest(0)
	if rootResp.err != nil {
		return &Response{
			status: status.Code(rootResp.err),
			err:    rootResp.err,
		}
	}
	root, err := unmarshalLogRoot(rootResp.getLatestResult.SignedLogRoot.LogRoot)
	if err != nil {
		return &Response{
			status: status.Code(rootResp.err),
			err:    rootResp.err,
		}
	}

	// issue 1308: if the tree is empty, there's no way we can return a proof
	if root.TreeSize == 0 {
		return &Response{
			status: codes.NotFound,
			err:    status.Error(codes.NotFound, "tree is empty"),
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
		for _, proof := range resp.Proof {
			if err := v.VerifyInclusionByHash(&root, hashValue, proof); err != nil {
				return &Response{
					status: status.Code(err),
					err:    err,
				}
			}
		}
		// Return an inclusion proof response with the requested
		return &Response{
			status: status.Code(err),
			err:    err,
			getProofResult: &trillian.GetInclusionProofByHashResponse{
				Proof:         resp.Proof,
				SignedLogRoot: rootResp.getLatestResult.SignedLogRoot,
			},
		}
	}

	return &Response{
		status: status.Code(err),
		err:    err,
	}
}

func (t *TrillianClient) getLatest(leafSizeInt int64) *Response {

	ctx, cancel := context.WithTimeout(t.context, 20*time.Second)
	defer cancel()

	resp, err := t.client.GetLatestSignedLogRoot(ctx,
		&trillian.GetLatestSignedLogRootRequest{
			LogId:         t.logID,
			FirstTreeSize: leafSizeInt,
		})

	return &Response{
		status:          status.Code(err),
		err:             err,
		getLatestResult: resp,
	}
}

func (t *TrillianClient) getConsistencyProof(firstSize, lastSize int64) *Response {

	ctx, cancel := context.WithTimeout(t.context, 20*time.Second)
	defer cancel()

	resp, err := t.client.GetConsistencyProof(ctx,
		&trillian.GetConsistencyProofRequest{
			LogId:          t.logID,
			FirstTreeSize:  firstSize,
			SecondTreeSize: lastSize,
		})

	return &Response{
		status:                    status.Code(err),
		err:                       err,
		getConsistencyProofResult: resp,
	}
}

func createAndInitTree(ctx context.Context, adminClient trillian.TrillianAdminClient, logClient trillian.TrillianLogClient) (*trillian.Tree, error) {
	t, err := adminClient.CreateTree(ctx, &trillian.CreateTreeRequest{
		Tree: &trillian.Tree{
			TreeType:        trillian.TreeType_LOG,
			TreeState:       trillian.TreeState_ACTIVE,
			MaxRootDuration: durationpb.New(time.Hour),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create tree: %w", err)
	}

	if err := client.InitLog(ctx, t, logClient); err != nil {
		return nil, fmt.Errorf("init log: %w", err)
	}
	log.Logger.Infof("Created new tree with ID: %v", t.TreeId)
	return t, nil
}
