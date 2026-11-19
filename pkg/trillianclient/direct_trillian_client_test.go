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
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/trillian"
	"github.com/google/trillian/testonly"
	"github.com/google/trillian/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/transparency-dev/merkle/rfc6962"
	spb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDirectClient_GetLatest(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	slr := mkSLR(t, 5, make([]byte, 32))
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(
		&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: slr}, nil,
	).Times(1)

	conn := dialMock(t, s.Addr)
	tc := newDirectTrillianClient(trillian.NewTrillianLogClient(conn), 42)

	resp := tc.GetLatest(context.Background())
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
	require.NotNil(t, resp.GetLatestResult)
	require.NotNil(t, resp.GetLatestResult.SignedLogRoot)

	var got types.LogRootV1
	require.NoError(t, got.UnmarshalBinary(resp.GetLatestResult.SignedLogRoot.LogRoot))
	require.EqualValues(t, 5, got.TreeSize)
}

func TestDirectClient_Close_DoesNotAffectRPCs(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	slr := mkSLR(t, 3, make([]byte, 32))
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(
		&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: slr}, nil,
	).Times(1)

	conn := dialMock(t, s.Addr)
	tc := newDirectTrillianClient(trillian.NewTrillianLogClient(conn), 42)

	// Close is intentionally a no-op for the simple client.
	tc.Close()

	resp := tc.GetLatest(context.Background())
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
}

func TestDirectClient_GetConsistencyProof(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	s.Log.EXPECT().GetConsistencyProof(gomock.Any(), gomock.Any()).Return(
		&trillian.GetConsistencyProofResponse{
			Proof: &trillian.Proof{Hashes: [][]byte{make([]byte, 32)}},
		}, nil,
	).Times(1)

	conn := dialMock(t, s.Addr)
	tc := newDirectTrillianClient(trillian.NewTrillianLogClient(conn), 42)

	resp := tc.GetConsistencyProof(context.Background(), 1, 5)
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
	require.NotNil(t, resp.GetConsistencyProofResult)
}

func TestDirectClient_GetLeavesByRange(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	s.Log.EXPECT().GetLeavesByRange(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req *trillian.GetLeavesByRangeRequest) (*trillian.GetLeavesByRangeResponse, error) {
			require.EqualValues(t, 42, req.LogId)
			require.EqualValues(t, 0, req.StartIndex)
			require.EqualValues(t, 1, req.Count)
			return &trillian.GetLeavesByRangeResponse{
				Leaves: []*trillian.LogLeaf{{LeafIndex: 0, MerkleLeafHash: make([]byte, 32)}},
			}, nil
		},
	).Times(1)

	conn := dialMock(t, s.Addr)
	tc := newDirectTrillianClient(trillian.NewTrillianLogClient(conn), 42)

	resp := tc.GetLeavesByRange(context.Background(), 0, 1)
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
	require.NotNil(t, resp.GetLeavesByRangeResult)
	require.Len(t, resp.GetLeavesByRangeResult.Leaves, 1)
}

func TestDirectClient_GetLeafWithoutProof_DelegatesToRange(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	s.Log.EXPECT().GetLeavesByRange(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req *trillian.GetLeavesByRangeRequest) (*trillian.GetLeavesByRangeResponse, error) {
			require.EqualValues(t, 42, req.LogId)
			require.EqualValues(t, 7, req.StartIndex)
			require.EqualValues(t, 1, req.Count)
			return &trillian.GetLeavesByRangeResponse{
				Leaves: []*trillian.LogLeaf{{LeafIndex: 7, MerkleLeafHash: make([]byte, 32)}},
			}, nil
		},
	).Times(1)

	conn := dialMock(t, s.Addr)
	tc := newDirectTrillianClient(trillian.NewTrillianLogClient(conn), 42)

	resp := tc.GetLeafWithoutProof(context.Background(), 7)
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
	require.NotNil(t, resp.GetLeavesByRangeResult)
	require.Len(t, resp.GetLeavesByRangeResult.Leaves, 1)
}

func mkSLRWithTimestamp(t *testing.T, size uint64, rootHash []byte, tsNanos uint64) *trillian.SignedLogRoot {
	t.Helper()
	lr := &types.LogRootV1{TreeSize: size, RootHash: rootHash, TimestampNanos: tsNanos}
	b, err := lr.MarshalBinary()
	require.NoError(t, err)
	return &trillian.SignedLogRoot{LogRoot: b}
}

func TestDirectClient_AddLeaf_NoFirstTreeSizeAndWaitsForTreeSizeIncrease(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	hasher := rfc6962.DefaultHasher
	h0 := hasher.HashLeaf([]byte("leaf-0"))
	h1 := hasher.HashLeaf([]byte("leaf-1"))
	leafVal := []byte("our-leaf")
	h2 := hasher.HashLeaf(leafVal)
	h01 := hasher.HashChildren(h0, h1)
	root3 := hasher.HashChildren(h01, h2)

	// Roots returned across successive GetLatestSignedLogRoot calls:
	// 1. beforeRoot (TreeSize=1, ts=100)
	// 2. poll 1: timestamp-only refresh (TreeSize=1, ts=200) -> must NOT trigger GetInclusionProofByHash
	// 3. poll 2: another batch landed (TreeSize=2, ts=300) -> GetInclusionProofByHash returns NotFound
	// 4. poll 3: our batch landed (TreeSize=3, ts=400) -> GetInclusionProofByHash succeeds (reusing this root!)
	roots := []*trillian.SignedLogRoot{
		mkSLRWithTimestamp(t, 1, h0, 100),
		mkSLRWithTimestamp(t, 1, h0, 200),
		mkSLRWithTimestamp(t, 2, h01, 300),
		mkSLRWithTimestamp(t, 3, root3, 400),
	}

	var rootCall atomic.Int32
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			assert.EqualValues(t, 42, req.LogId)
			// Must NEVER request a consistency proof via FirstTreeSize > 0.
			assert.Zero(t, req.FirstTreeSize)
			idx := int(rootCall.Add(1)) - 1
			return &trillian.GetLatestSignedLogRootResponse{SignedLogRoot: roots[idx]}, nil
		},
	).Times(len(roots))

	s.Log.EXPECT().QueueLeaf(gomock.Any(), gomock.Any()).Return(
		&trillian.QueueLeafResponse{
			QueuedLeaf: &trillian.QueuedLogLeaf{
				Leaf: &trillian.LogLeaf{
					LeafValue:      leafVal,
					MerkleLeafHash: h2,
				},
			},
		}, nil,
	).Times(1)

	var proofCall atomic.Int32
	s.Log.EXPECT().GetInclusionProofByHash(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req *trillian.GetInclusionProofByHashRequest) (*trillian.GetInclusionProofByHashResponse, error) {
			call := proofCall.Add(1)
			switch call {
			case 1:
				// First proof lookup must only happen once TreeSize increased to 2 (skipping TreeSize=1).
				require.EqualValues(t, 2, req.TreeSize)
				return nil, status.Error(codes.NotFound, "not sequenced yet")
			case 2:
				require.EqualValues(t, 3, req.TreeSize)
				return &trillian.GetInclusionProofByHashResponse{
					Proof: []*trillian.Proof{{
						LeafIndex: 2,
						Hashes:    [][]byte{h01},
					}},
				}, nil
			default:
				t.Fatalf("unexpected GetInclusionProofByHash call %d", call)
				return nil, nil
			}
		},
	).Times(2)

	s.Log.EXPECT().GetLeavesByRange(gomock.Any(), gomock.Any()).Return(
		&trillian.GetLeavesByRangeResponse{
			Leaves: []*trillian.LogLeaf{{
				LeafIndex:      2,
				LeafValue:      leafVal,
				MerkleLeafHash: h2,
			}},
		}, nil,
	).Times(1)

	conn := dialMock(t, s.Addr)
	tc := newDirectTrillianClient(trillian.NewTrillianLogClient(conn), 42)
	tc.pollMin = time.Millisecond

	resp := tc.AddLeaf(context.Background(), leafVal)
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
	require.NotNil(t, resp.GetLeafAndProofResult)
	require.EqualValues(t, 2, resp.GetLeafAndProofResult.Leaf.LeafIndex)
}

func TestDirectClient_AddLeaf_DuplicateShortCircuits(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(
		&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: mkSLR(t, 5, make([]byte, 32))}, nil,
	).Times(1)

	s.Log.EXPECT().QueueLeaf(gomock.Any(), gomock.Any()).Return(
		&trillian.QueueLeafResponse{
			QueuedLeaf: &trillian.QueuedLogLeaf{
				Leaf:   &trillian.LogLeaf{LeafValue: []byte("dup")},
				Status: &spb.Status{Code: int32(codes.AlreadyExists)},
			},
		}, nil,
	).Times(1)

	conn := dialMock(t, s.Addr)
	tc := newDirectTrillianClient(trillian.NewTrillianLogClient(conn), 42)

	resp := tc.AddLeaf(context.Background(), []byte("dup"))
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
	require.NotNil(t, resp.GetAddResult)
	require.EqualValues(t, codes.AlreadyExists, resp.GetAddResult.QueuedLeaf.Status.Code)
}

type afterQueueClient struct {
	trillian.TrillianLogClient
	afterQueue func()
}

func (c *afterQueueClient) QueueLeaf(ctx context.Context, in *trillian.QueueLeafRequest, opts ...grpc.CallOption) (*trillian.QueueLeafResponse, error) {
	resp, err := c.TrillianLogClient.QueueLeaf(ctx, in, opts...)
	c.afterQueue()
	return resp, err
}

func TestDirectClient_AddLeaf_ContextCanceled(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	leafVal := []byte("cancel-me")
	leafHash := rfc6962.DefaultHasher.HashLeaf(leafVal)
	slr := mkSLR(t, 1, make([]byte, 32))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			assert.Zero(t, req.FirstTreeSize)
			return &trillian.GetLatestSignedLogRootResponse{SignedLogRoot: slr}, nil
		},
	).Times(1)

	s.Log.EXPECT().QueueLeaf(gomock.Any(), gomock.Any()).Return(
		&trillian.QueueLeafResponse{
			QueuedLeaf: &trillian.QueuedLogLeaf{
				Leaf: &trillian.LogLeaf{
					LeafValue:      leafVal,
					MerkleLeafHash: leafHash,
				},
			},
		}, nil,
	).Times(1)

	conn := dialMock(t, s.Addr)
	wrapped := &afterQueueClient{
		TrillianLogClient: trillian.NewTrillianLogClient(conn),
		afterQueue:        cancel,
	}
	tc := newDirectTrillianClient(wrapped, 42)
	tc.pollMin = time.Hour

	resp := tc.AddLeaf(ctx, leafVal)
	require.Error(t, resp.Err)
	require.Equal(t, codes.Canceled, resp.Status)
	require.NotNil(t, resp.GetAddResult)
}
