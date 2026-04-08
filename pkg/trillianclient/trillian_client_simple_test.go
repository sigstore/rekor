//
// Copyright 2025 The Sigstore Authors.
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
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/trillian"
	"github.com/google/trillian/testonly"
	"github.com/google/trillian/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestSimpleClient_GetLatest(t *testing.T) {
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
	tc := newSimpleTrillianClient(trillian.NewTrillianLogClient(conn), 42)

	resp := tc.GetLatest(context.Background(), 0)
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
	require.NotNil(t, resp.GetLatestResult)
	require.NotNil(t, resp.GetLatestResult.SignedLogRoot)

	var got types.LogRootV1
	require.NoError(t, got.UnmarshalBinary(resp.GetLatestResult.SignedLogRoot.LogRoot))
	require.EqualValues(t, 5, got.TreeSize)
}

func TestSimpleClient_GetLatest_WithFirstTreeSize(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	slr := mkSLR(t, 10, make([]byte, 32))
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			// Verify FirstTreeSize is passed through to Trillian
			require.EqualValues(t, 5, req.FirstTreeSize)
			return &trillian.GetLatestSignedLogRootResponse{SignedLogRoot: slr}, nil
		},
	).Times(1)

	conn := dialMock(t, s.Addr)
	tc := newSimpleTrillianClient(trillian.NewTrillianLogClient(conn), 42)

	resp := tc.GetLatest(context.Background(), 5)
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
}

func TestSimpleClient_Close_DoesNotAffectRPCs(t *testing.T) {
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
	tc := newSimpleTrillianClient(trillian.NewTrillianLogClient(conn), 42)

	// Close is intentionally a no-op for the simple client.
	tc.Close()

	resp := tc.GetLatest(context.Background(), 0)
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
}

func TestSimpleClient_GetConsistencyProof(t *testing.T) {
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
	tc := newSimpleTrillianClient(trillian.NewTrillianLogClient(conn), 42)

	resp := tc.GetConsistencyProof(context.Background(), 1, 5)
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
	require.NotNil(t, resp.GetConsistencyProofResult)
}

func TestSimpleClient_GetLeavesByRange(t *testing.T) {
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
	tc := newSimpleTrillianClient(trillian.NewTrillianLogClient(conn), 42)

	resp := tc.GetLeavesByRange(context.Background(), 0, 1)
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
	require.NotNil(t, resp.GetLeavesByRangeResult)
	require.Len(t, resp.GetLeavesByRangeResult.Leaves, 1)
}

func TestSimpleClient_GetLeafWithoutProof_DelegatesToRange(t *testing.T) {
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
	tc := newSimpleTrillianClient(trillian.NewTrillianLogClient(conn), 42)

	resp := tc.GetLeafWithoutProof(context.Background(), 7)
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
	require.NotNil(t, resp.GetLeavesByRangeResult)
	require.Len(t, resp.GetLeavesByRangeResult.Leaves, 1)
}
