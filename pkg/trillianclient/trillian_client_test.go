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
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/testonly"
	"github.com/google/trillian/types"
	"github.com/stretchr/testify/require"
	"github.com/transparency-dev/merkle/rfc6962"
	"go.uber.org/goleak"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// helper to build a SignedLogRoot with given tree size and root hash
func mkSLR(t *testing.T, size uint64, rootHash []byte) *trillian.SignedLogRoot {
	t.Helper()
	lr := &types.LogRootV1{TreeSize: size, RootHash: rootHash}
	b, err := lr.MarshalBinary()
	require.NoError(t, err)
	return &trillian.SignedLogRoot{LogRoot: b}
}

func dialMock(t *testing.T, addr string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestEnsureStartedAndGetLatest(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	// Initial root (empty tree)
	slr := mkSLR(t, 0, make([]byte, 32))
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: slr}, nil).MinTimes(1)

	conn := dialMock(t, s.Addr)
	tc := newTrillianClient(trillian.NewTrillianLogClient(conn), 42, DefaultTrillianClientConfig())
	t.Cleanup(tc.Close)

	resp := tc.GetLatest(context.Background(), 0)
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
	require.NotNil(t, resp.GetLatestResult)
	require.NotNil(t, resp.GetLatestResult.SignedLogRoot)

	// Unmarshal and check size
	var got types.LogRootV1
	require.NoError(t, got.UnmarshalBinary(resp.GetLatestResult.SignedLogRoot.LogRoot))
	require.EqualValues(t, 0, got.TreeSize)
}

// Note: waiting for an advance via client.WaitForRootUpdate is exercised indirectly
// in other tests (AddLeaf), and is hard to deterministically simulate across
// environments with the mock server; we avoid a direct "firstSize" wait test here.

func TestGetLeafAndProofByIndex_VerifiesProof(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	// Tree of size 1, root equals leaf hash. Empty proof should verify.
	rootHash := make([]byte, 32)
	slr1 := mkSLR(t, 1, rootHash)
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: slr1}, nil).MinTimes(1)

	s.Log.EXPECT().GetEntryAndProof(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, r *trillian.GetEntryAndProofRequest) (*trillian.GetEntryAndProofResponse, error) {
			// Ensure we were asked for the current tree size
			if r.TreeSize != 1 || r.LeafIndex != 0 {
				return nil, status.Error(codes.InvalidArgument, "unexpected request")
			}
			return &trillian.GetEntryAndProofResponse{
				Leaf:  &trillian.LogLeaf{MerkleLeafHash: rootHash},
				Proof: &trillian.Proof{LeafIndex: 0, Hashes: nil},
			}, nil
		},
	).Times(1)

	conn := dialMock(t, s.Addr)
	tc := newTrillianClient(trillian.NewTrillianLogClient(conn), 9, DefaultTrillianClientConfig())
	t.Cleanup(tc.Close)

	resp := tc.GetLeafAndProofByIndex(context.Background(), 0)
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
	require.NotNil(t, resp.GetLeafAndProofResult)
}

func TestGetLeafAndProofByHash_VerifiesProof(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	rootHash := make([]byte, 32)
	slr1 := mkSLR(t, 1, rootHash)
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: slr1}, nil).MinTimes(1)

	// Inclusion proof for hash -> index 0, empty path is valid in size=1
	s.Log.EXPECT().GetInclusionProofByHash(gomock.Any(), gomock.Any()).Return(
		&trillian.GetInclusionProofByHashResponse{Proof: []*trillian.Proof{{LeafIndex: 0, Hashes: nil}}}, nil,
	).Times(1)

	s.Log.EXPECT().GetEntryAndProof(gomock.Any(), gomock.Any()).Return(
		&trillian.GetEntryAndProofResponse{Leaf: &trillian.LogLeaf{MerkleLeafHash: rootHash}, Proof: &trillian.Proof{LeafIndex: 0, Hashes: nil}}, nil,
	).Times(1)

	conn := dialMock(t, s.Addr)
	tc := newTrillianClient(trillian.NewTrillianLogClient(conn), 13, DefaultTrillianClientConfig())
	t.Cleanup(tc.Close)

	resp := tc.GetLeafAndProofByHash(context.Background(), rootHash)
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
	require.NotNil(t, resp.GetLeafAndProofResult)
}

func TestAddLeaf_HappyPath(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, opt) })
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	leafHash := make([]byte, 32) // leaf 0 hash

	// We'll simulate a root advance from size=0 to size=2 and return a
	// proof for leaf index 0 with a single sibling. Compute a consistent
	// root hash for size=2 so verification succeeds.
	sibling := bytes.Repeat([]byte{0x7f}, 32) // arbitrary sibling hash
	root2 := rfc6962.DefaultHasher.HashChildren(leafHash, sibling)
	slr0 := mkSLR(t, 0, make([]byte, 32))

	// QueueLeaf returns quickly
	s.Log.EXPECT().QueueLeaf(gomock.Any(), gomock.Any()).Return(&trillian.QueueLeafResponse{
		QueuedLeaf: &trillian.QueuedLogLeaf{Leaf: &trillian.LogLeaf{MerkleLeafHash: leafHash}},
	}, nil).Times(1)

	// We bypass ensureStarted's network init and the updater by pre-initializing
	// the client snapshot and verifier, then manually advancing the snapshot.

	// Inclusion proof by hash: success for size=2 with sibling path
	s.Log.EXPECT().GetInclusionProofByHash(gomock.Any(), gomock.Any()).Return(
		&trillian.GetInclusionProofByHashResponse{Proof: []*trillian.Proof{{LeafIndex: 0, Hashes: [][]byte{sibling}}}}, nil,
	).Times(1)

	// After inclusion, client fetches leaf by index without proof to get server-populated fields
	s.Log.EXPECT().GetLeavesByRange(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, r *trillian.GetLeavesByRangeRequest) (*trillian.GetLeavesByRangeResponse, error) {
			if r.Count != 1 || r.StartIndex != 0 {
				return nil, status.Error(codes.InvalidArgument, "unexpected range request")
			}
			return &trillian.GetLeavesByRangeResponse{Leaves: []*trillian.LogLeaf{{MerkleLeafHash: leafHash}}}, nil
		},
	).Times(1)

	conn := dialMock(t, s.Addr)
	tc := newTrillianClient(trillian.NewTrillianLogClient(conn), 21, DefaultTrillianClientConfig())
	// Pre-initialize
	tc.started = true
	tc.v = client.NewLogVerifier(rfc6962.DefaultHasher)
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0, RootHash: make([]byte, 32)}, signed: slr0})
	// Advance snapshot to size=2 after a short delay to release waiters
	go func() {
		time.Sleep(20 * time.Millisecond)
		b, _ := (&types.LogRootV1{TreeSize: 2, RootHash: root2}).MarshalBinary()
		tc.mu.Lock()
		tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 2, RootHash: root2}, signed: &trillian.SignedLogRoot{LogRoot: b}})
		tc.cond.Broadcast()
		tc.mu.Unlock()
	}()
	t.Cleanup(tc.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp := tc.AddLeaf(ctx, []byte("hello"))
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
	require.NotNil(t, resp.GetAddResult)
	require.NotNil(t, resp.GetLeafAndProofResult)
}

func TestGetLatestFirstSizeCanceledOnClose(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, opt) })
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	// Always return size=0 so waiter would block
	slr0 := mkSLR(t, 0, make([]byte, 32))
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: slr0}, nil).MinTimes(1)

	conn := dialMock(t, s.Addr)
	tc := newTrillianClient(trillian.NewTrillianLogClient(conn), 33, DefaultTrillianClientConfig())

	done := make(chan *Response, 1)
	go func() {
		done <- tc.GetLatest(context.Background(), 1) // would block until size>=1
	}()

	// Give it a moment to start waiting
	time.Sleep(50 * time.Millisecond)
	tc.Close()

	select {
	case r := <-done:
		require.Error(t, r.Err)
		require.Equal(t, codes.Canceled, r.Status)
	case <-time.After(2 * time.Second):
		t.Fatal("GetLatest did not return after Close")
	}
}

func TestEnsureStartedError(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(nil, status.Error(codes.Unavailable, "boom")).Times(1)

	conn := dialMock(t, s.Addr)
	tc := newTrillianClient(trillian.NewTrillianLogClient(conn), 99, DefaultTrillianClientConfig())
	t.Cleanup(tc.Close)

	resp := tc.GetLatest(context.Background(), 0)
	require.Error(t, resp.Err)
	require.Equal(t, codes.Unavailable, resp.Status)
}

func TestWaitForRootAtLeast_BroadcastWakesAll(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, opt) })
	tc := newTrillianClient(nil, 100, DefaultTrillianClientConfig())
	// Start with size 0
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}})

	const waiters = 10
	var wg sync.WaitGroup
	wg.Add(waiters)

	errs := make(chan error, waiters)
	for i := 0; i < waiters; i++ {
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			errs <- tc.waitForRootAtLeast(ctx, 5)
		}()
	}

	// Give goroutines time to block on cond.Wait
	time.Sleep(20 * time.Millisecond)

	// Publish new root and broadcast
	tc.mu.Lock()
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 5}})
	tc.cond.Broadcast()
	tc.mu.Unlock()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
		close(errs)
		for e := range errs {
			require.NoError(t, e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiters did not unblock after broadcast")
	}
}

func TestGetLatest_WithFirstSize_BroadcastWakesAll(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, opt) })
	tc := newTrillianClient(nil, 101, DefaultTrillianClientConfig())
	// Mark as started to bypass network init in GetLatest
	tc.started = true
	// initial snapshot with size 0
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}, signed: mkSLR(t, 0, make([]byte, 32))})

	const waiters = 8
	var wg sync.WaitGroup
	wg.Add(waiters)

	results := make(chan *Response, waiters)
	for i := 0; i < waiters; i++ {
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			results <- tc.GetLatest(ctx, 5)
		}()
	}

	// Small delay to let goroutines block
	time.Sleep(20 * time.Millisecond)

	// Publish root size 5 and broadcast so all GetLatest unblock
	lr := &types.LogRootV1{TreeSize: 5, RootHash: make([]byte, 32)}
	b, err := lr.MarshalBinary()
	require.NoError(t, err)
	tc.mu.Lock()
	tc.snapshot.Store(rootSnapshot{root: *lr, signed: &trillian.SignedLogRoot{LogRoot: b}})
	tc.cond.Broadcast()
	tc.mu.Unlock()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
		close(results)
		for r := range results {
			require.NoError(t, r.Err)
			require.Equal(t, codes.OK, r.Status)
			require.NotNil(t, r.GetLatestResult)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("GetLatest waiters did not unblock after broadcast")
	}
}

func TestEnsureStarted_SingleRPCWithFanIn(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, opt) })
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	slr := mkSLR(t, 0, make([]byte, 32))
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, r *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			time.Sleep(30 * time.Millisecond)
			return &trillian.GetLatestSignedLogRootResponse{SignedLogRoot: slr}, nil
		},
	).MinTimes(1)

	conn := dialMock(t, s.Addr)
	tc := newTrillianClient(trillian.NewTrillianLogClient(conn), 222, DefaultTrillianClientConfig())
	t.Cleanup(tc.Close)

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			r := tc.GetLatest(ctx, 0)
			errs <- r.Err
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		require.NoError(t, e)
	}
}

func TestWaitForRootAtLeast_SpuriousBroadcastIgnored(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, opt) })
	tc := newTrillianClient(nil, 303, DefaultTrillianClientConfig())
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 1}})

	const waiters = 6
	var wg sync.WaitGroup
	wg.Add(waiters)
	results := make(chan error, waiters)
	for i := 0; i < waiters; i++ {
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			results <- tc.waitForRootAtLeast(ctx, 5)
		}()
	}

	// Give them time to block
	time.Sleep(20 * time.Millisecond)

	// Broadcast without changing size; wait briefly and ensure nobody finished
	tc.mu.Lock()
	tc.cond.Broadcast()
	tc.mu.Unlock()
	time.Sleep(30 * time.Millisecond)
	require.Zero(t, len(results), "waiters should not exit on spurious broadcast")

	// Now increase size and broadcast; everyone should complete
	tc.mu.Lock()
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 5}})
	tc.cond.Broadcast()
	tc.mu.Unlock()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		close(results)
		for e := range results {
			require.NoError(t, e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiters did not complete after size increased")
	}
}

func TestSnapshotConcurrentReadersWriters_NoDataRace(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, opt) })
	tc := newTrillianClient(nil, 404, DefaultTrillianClientConfig())
	tc.started = true
	// Provide a minimal signed root so GetLatest can return without NotFound
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}, signed: mkSLR(t, 0, make([]byte, 32))})

	stop := make(chan struct{})

	// Writer rapidly updates snapshot, broadcasting each time
	go func() {
		ticker := time.NewTicker(1 * time.Millisecond)
		defer ticker.Stop()
		sz := uint64(0)
		for i := 0; i < 100; i++ {
			<-ticker.C
			sz++
			lr := &types.LogRootV1{TreeSize: sz}
			b, _ := lr.MarshalBinary()
			tc.mu.Lock()
			tc.snapshot.Store(rootSnapshot{root: *lr, signed: &trillian.SignedLogRoot{LogRoot: b}})
			tc.cond.Broadcast()
			tc.mu.Unlock()
		}
		close(stop)
	}()

	// Readers call GetLatest repeatedly
	const readers = 16
	var wg sync.WaitGroup
	wg.Add(readers)
	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				r := tc.GetLatest(context.Background(), 0)
				require.NoError(t, r.Err)
				require.NotNil(t, r.GetLatestResult)
			}
		}()
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		// success
	case <-time.After(500 * time.Millisecond):
		t.Fatal("concurrent readers did not complete in time")
	}
}

func TestEnsureStartedDeadlineRespected(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	// Server handler sleeps longer than client deadline; client should return DeadlineExceeded
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, r *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			time.Sleep(200 * time.Millisecond)
			return &trillian.GetLatestSignedLogRootResponse{SignedLogRoot: mkSLR(t, 0, make([]byte, 32))}, nil
		},
	).MinTimes(1)

	conn := dialMock(t, s.Addr)
	tc := newTrillianClient(trillian.NewTrillianLogClient(conn), 606, DefaultTrillianClientConfig())
	t.Cleanup(tc.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	resp := tc.GetLatest(ctx, 0)
	require.Error(t, resp.Err)
	require.Equal(t, codes.DeadlineExceeded, resp.Status)
}
