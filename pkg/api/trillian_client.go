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

	"github.com/google/trillian/merkle/logverifier"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/pkg/errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/types"
)

type TrillianClient struct {
	client  trillian.TrillianLogClient
	logID   int64
	context context.Context
}

func NewTrillianClient(ctx context.Context) TrillianClient {
	return TrillianClient{
		client:  api.logClient,
		logID:   api.logID,
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

func (t *TrillianClient) root() (types.LogRootV1, error) {
	rqst := &trillian.GetLatestSignedLogRootRequest{
		LogId: t.logID,
	}
	resp, err := t.client.GetLatestSignedLogRoot(t.context, rqst)
	if err != nil {
		return types.LogRootV1{}, err
	}
	var root types.LogRootV1
	if err := root.UnmarshalBinary(resp.SignedLogRoot.LogRoot); err != nil {
		return types.LogRootV1{}, err
	}
	return root, nil
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

	root, err := t.root()
	if err != nil {
		return &Response{
			status: status.Code(err),
			err:    err,
		}
	}

	resp, err := t.client.GetEntryAndProof(ctx,
		&trillian.GetEntryAndProofRequest{
			LogId:     t.logID,
			LeafIndex: index,
			TreeSize:  int64(root.TreeSize),
		})

	if resp != nil && resp.Proof != nil {
		logVerifier := logverifier.New(rfc6962.DefaultHasher)
		if err := logVerifier.VerifyInclusionProof(index, int64(root.TreeSize), resp.Proof.Hashes, root.RootHash, resp.GetLeaf().MerkleLeafHash); err != nil {
			return &Response{
				status: status.Code(err),
				err:    err,
			}
		}
	}

	return &Response{
		status:                status.Code(err),
		err:                   err,
		getLeafAndProofResult: resp,
	}
}

func (t *TrillianClient) getProofByHash(hashValue []byte) *Response {
	ctx, cancel := context.WithTimeout(t.context, 20*time.Second)
	defer cancel()

	root, err := t.root()
	if err != nil {
		return &Response{
			status: status.Code(err),
			err:    err,
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
	}

	return &Response{
		status:         status.Code(err),
		err:            err,
		getProofResult: resp,
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
	// First look for and use an existing tree
	trees, err := adminClient.ListTrees(ctx, &trillian.ListTreesRequest{})
	if err != nil {
		return nil, errors.Wrap(err, "list trees")
	}

	for _, t := range trees.Tree {
		if t.TreeType == trillian.TreeType_LOG {
			return t, nil
		}
	}

	// Otherwise create and initialize one
	t, err := adminClient.CreateTree(ctx, &trillian.CreateTreeRequest{
		Tree: &trillian.Tree{
			TreeType:        trillian.TreeType_LOG,
			TreeState:       trillian.TreeState_ACTIVE,
			MaxRootDuration: durationpb.New(time.Hour),
		},
	})
	if err != nil {
		return nil, errors.Wrap(err, "create tree")
	}

	if err := client.InitLog(ctx, t, logClient); err != nil {
		return nil, errors.Wrap(err, "init log")
	}
	return t, nil
}
