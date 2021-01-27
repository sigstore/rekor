/*
Copyright © 2020 Luke Hinds <lhinds@redhat.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package api

import (
	"context"
	"time"

	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/crypto/sigpb"
	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/google/trillian/types"
)

type TrillianClient struct {
	client  trillian.TrillianLogClient
	logID   int64
	context context.Context
	pubkey  *keyspb.PublicKey
	tree    *trillian.Tree
}

type Response struct {
	status                    codes.Code
	err                       error
	getAddResult              *trillian.QueueLeafResponse
	getLeafResult             *trillian.GetLeavesByHashResponse
	getProofResult            *trillian.GetInclusionProofByHashResponse
	getLeafByRangeResult      *trillian.GetLeavesByRangeResponse
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
	verifier, err := client.NewLogVerifierFromTree(t.tree)
	if err != nil {
		return &Response{
			status:       status.Code(err),
			err:          err,
			getAddResult: resp,
		}
	}
	logClient := client.New(t.logID, t.client, verifier, root)
	if err := logClient.WaitForInclusion(t.context, byteValue); err != nil {
		return &Response{
			status:       status.Code(err),
			err:          err,
			getAddResult: resp,
		}
	}

	leafResp := t.getLeafByHash([][]byte{resp.QueuedLeaf.Leaf.MerkleLeafHash})
	if leafResp.err != nil {
		return &Response{
			status:       status.Code(leafResp.err),
			err:          leafResp.err,
			getAddResult: resp,
		}
	}

	//overwrite queued leaf that doesn't have index set
	resp.QueuedLeaf.Leaf = leafResp.getLeafResult.Leaves[0]

	return &Response{
		status:       status.Code(err),
		err:          err,
		getAddResult: resp,
	}
}

func (t *TrillianClient) getLeafByHash(hashValues [][]byte) *Response {
	rqst := &trillian.GetLeavesByHashRequest{
		LogId:    t.logID,
		LeafHash: hashValues,
	}

	resp, err := t.client.GetLeavesByHash(t.context, rqst)

	return &Response{
		status:        status.Code(err),
		err:           err,
		getLeafResult: resp,
	}
}

func (t *TrillianClient) getLeafByIndex(index int64) *Response {

	ctx, cancel := context.WithTimeout(t.context, 20*time.Second)
	defer cancel()

	resp, err := t.client.GetLeavesByRange(ctx,
		&trillian.GetLeavesByRangeRequest{
			LogId:      t.logID,
			StartIndex: index,
			Count:      1,
		})

	return &Response{
		status:               status.Code(err),
		err:                  err,
		getLeafByRangeResult: resp,
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

	v := merkle.NewLogVerifier(rfc6962.DefaultHasher)

	if resp != nil {
		for _, proof := range resp.Proof {
			if err := v.VerifyInclusionProof(proof.LeafIndex, int64(root.TreeSize), proof.GetHashes(), root.RootHash, hashValue); err != nil {
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
		return nil, err
	}

	for _, t := range trees.Tree {
		if t.TreeType == trillian.TreeType_LOG {
			return t, nil
		}
	}

	// Otherwise create and initialize one
	t, err := adminClient.CreateTree(ctx, &trillian.CreateTreeRequest{
		Tree: &trillian.Tree{
			TreeType:           trillian.TreeType_LOG,
			HashStrategy:       trillian.HashStrategy_RFC6962_SHA256,
			HashAlgorithm:      sigpb.DigitallySigned_SHA256,
			SignatureAlgorithm: sigpb.DigitallySigned_ECDSA,
			TreeState:          trillian.TreeState_ACTIVE,
			MaxRootDuration:    ptypes.DurationProto(time.Hour),
		},
		KeySpec: &keyspb.Specification{
			Params: &keyspb.Specification_EcdsaParams{
				EcdsaParams: &keyspb.Specification_ECDSA{},
			},
		},
	})
	if err != nil {
		return nil, err
	}

	if err := client.InitLog(ctx, t, logClient); err != nil {
		return nil, err
	}
	return t, nil
}
