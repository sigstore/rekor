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
	"runtime"
	"sync"
	"sync/atomic"
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

// advanceRoot updates the cached snapshot and notifies waiters via the channel-per-caller mechanism.
func advanceRoot(t *testing.T, tc *TrillianClient, size uint64, rootHash []byte) {
	t.Helper()
	lr := &types.LogRootV1{TreeSize: size, RootHash: rootHash}
	b, err := lr.MarshalBinary()
	require.NoError(t, err)
	tc.mu.Lock()
	tc.snapshot.Store(rootSnapshot{root: *lr, signed: &trillian.SignedLogRoot{LogRoot: b}})
	tc.notifyWaiters(size)
	tc.mu.Unlock()
}

// waitForWaiters blocks until at least n callers have registered in tc.waiters,
// or fails the test after a timeout. Replaces fragile time.Sleep registration barriers.
func waitForWaiters(t *testing.T, tc *TrillianClient, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		tc.mu.Lock()
		got := len(tc.waiters)
		tc.mu.Unlock()
		if got >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d waiters to register, got %d", n, got)
		}
		runtime.Gosched()
	}
}

type fakeCloseTrackingClient struct {
	closeCalls int32
}

func (f *fakeCloseTrackingClient) AddLeaf(_ context.Context, _ []byte) *Response {
	return &Response{Status: codes.OK}
}

func (f *fakeCloseTrackingClient) GetLatest(_ context.Context, _ int64) *Response {
	return &Response{Status: codes.OK}
}

func (f *fakeCloseTrackingClient) GetLeafAndProofByHash(_ context.Context, _ []byte) *Response {
	return &Response{Status: codes.OK}
}

func (f *fakeCloseTrackingClient) GetLeafAndProofByIndex(_ context.Context, _ int64) *Response {
	return &Response{Status: codes.OK}
}

func (f *fakeCloseTrackingClient) GetConsistencyProof(_ context.Context, _, _ int64) *Response {
	return &Response{Status: codes.OK}
}

func (f *fakeCloseTrackingClient) GetLeavesByRange(_ context.Context, _, _ int64) *Response {
	return &Response{Status: codes.OK}
}

func (f *fakeCloseTrackingClient) GetLeafWithoutProof(_ context.Context, _ int64) *Response {
	return &Response{Status: codes.OK}
}

func (f *fakeCloseTrackingClient) Close() {
	atomic.AddInt32(&f.closeCalls, 1)
}

func (f *fakeCloseTrackingClient) CloseCalls() int32 {
	return atomic.LoadInt32(&f.closeCalls)
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
	tc := newTrillianClient(trillian.NewTrillianLogClient(conn), 42, DefaultConfig())
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
		func(_ context.Context, r *trillian.GetEntryAndProofRequest) (*trillian.GetEntryAndProofResponse, error) {
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
	tc := newTrillianClient(trillian.NewTrillianLogClient(conn), 9, DefaultConfig())
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

	// GetLeafAndProofByHash now calls GetLeavesByRange to fetch the leaf
	s.Log.EXPECT().GetLeavesByRange(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, r *trillian.GetLeavesByRangeRequest) (*trillian.GetLeavesByRangeResponse, error) {
			if r.Count != 1 || r.StartIndex != 0 {
				return nil, status.Error(codes.InvalidArgument, "unexpected range request")
			}
			return &trillian.GetLeavesByRangeResponse{Leaves: []*trillian.LogLeaf{{MerkleLeafHash: rootHash}}}, nil
		},
	).Times(1)

	conn := dialMock(t, s.Addr)
	tc := newTrillianClient(trillian.NewTrillianLogClient(conn), 13, DefaultConfig())
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
		func(_ context.Context, r *trillian.GetLeavesByRangeRequest) (*trillian.GetLeavesByRangeResponse, error) {
			if r.Count != 1 || r.StartIndex != 0 {
				return nil, status.Error(codes.InvalidArgument, "unexpected range request")
			}
			return &trillian.GetLeavesByRangeResponse{Leaves: []*trillian.LogLeaf{{MerkleLeafHash: leafHash}}}, nil
		},
	).Times(1)

	conn := dialMock(t, s.Addr)
	tc := newTrillianClient(trillian.NewTrillianLogClient(conn), 21, DefaultConfig())
	// Pre-initialize
	tc.started = true
	tc.v = client.NewLogVerifier(rfc6962.DefaultHasher)
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0, RootHash: make([]byte, 32)}, signed: slr0})
	// Advance snapshot to size=2 once AddLeaf has registered its inclusion waiter.
	go func() {
		waitForWaiters(t, tc, 1)
		advanceRoot(t, tc, 2, root2)
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
	tc := newTrillianClient(trillian.NewTrillianLogClient(conn), 33, DefaultConfig())

	done := make(chan *Response, 1)
	go func() {
		done <- tc.GetLatest(context.Background(), 1) // would block until size>=1
	}()

	waitForWaiters(t, tc, 1)
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
	tc := newTrillianClient(trillian.NewTrillianLogClient(conn), 99, DefaultConfig())
	t.Cleanup(tc.Close)

	resp := tc.GetLatest(context.Background(), 0)
	require.Error(t, resp.Err)
	require.Equal(t, codes.Unavailable, resp.Status)
}

func TestWaitForRootAtLeast_BroadcastWakesAll(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, opt) })
	tc := newTrillianClient(nil, 100, DefaultConfig())
	// Start with size 0
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}})
	t.Cleanup(tc.Close)

	const numWaiters = 10
	var wg sync.WaitGroup
	wg.Add(numWaiters)

	errs := make(chan error, numWaiters)
	for i := 0; i < numWaiters; i++ {
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			errs <- tc.waitForRootAtLeast(ctx, 5)
		}()
	}

	waitForWaiters(t, tc, numWaiters)

	// Publish new root and notify waiters
	advanceRoot(t, tc, 5, make([]byte, 32))

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
		close(errs)
		for e := range errs {
			require.NoError(t, e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiters did not unblock after notification")
	}
}

func TestGetLatest_WithFirstSize_BroadcastWakesAll(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, opt) })
	tc := newTrillianClient(nil, 101, DefaultConfig())
	// Mark as started to bypass network init in GetLatest
	tc.started = true
	// initial snapshot with size 0
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}, signed: mkSLR(t, 0, make([]byte, 32))})
	t.Cleanup(tc.Close)

	const numWaiters = 8
	var wg sync.WaitGroup
	wg.Add(numWaiters)

	results := make(chan *Response, numWaiters)
	for i := 0; i < numWaiters; i++ {
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			results <- tc.GetLatest(ctx, 5)
		}()
	}

	waitForWaiters(t, tc, numWaiters)

	// Publish root size 5 and notify waiters
	advanceRoot(t, tc, 5, make([]byte, 32))

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
		t.Fatal("GetLatest waiters did not unblock after notification")
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
		func(_ context.Context, _ *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			time.Sleep(30 * time.Millisecond)
			return &trillian.GetLatestSignedLogRootResponse{SignedLogRoot: slr}, nil
		},
	).Times(1)

	conn := dialMock(t, s.Addr)
	cfg := DefaultConfig()
	cfg.FrozenTreeIDs = map[int64]bool{222: true} // prevents updater RPC noise
	tc := newTrillianClient(trillian.NewTrillianLogClient(conn), 222, cfg)
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
	tc := newTrillianClient(nil, 303, DefaultConfig())
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 1}})
	t.Cleanup(tc.Close)

	const numWaiters = 6
	var wg sync.WaitGroup
	wg.Add(numWaiters)
	results := make(chan error, numWaiters)
	for i := 0; i < numWaiters; i++ {
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			results <- tc.waitForRootAtLeast(ctx, 5)
		}()
	}

	waitForWaiters(t, tc, numWaiters)

	// With channel-per-caller, there is no "spurious" broadcast; waiters are only
	// notified when their target size is met. Advance to size 3 (below target 5);
	// waiters for size 5 should remain registered.
	advanceRoot(t, tc, 3, make([]byte, 32))
	tc.mu.Lock()
	stillWaiting := len(tc.waiters)
	tc.mu.Unlock()
	require.Equal(t, numWaiters, stillWaiting, "waiters should remain registered when size is below target")

	// Now increase size to 5; everyone should complete
	advanceRoot(t, tc, 5, make([]byte, 32))

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
	tc := newTrillianClient(nil, 404, DefaultConfig())
	tc.started = true
	// Provide a minimal signed root so GetLatest can return without NotFound
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}, signed: mkSLR(t, 0, make([]byte, 32))})
	t.Cleanup(tc.Close)

	stop := make(chan struct{})

	// Writer rapidly updates snapshot, notifying waiters each time
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
			tc.notifyWaiters(sz)
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

func TestEnsureStarted_IgnoresCallerDeadline(t *testing.T) {
	// Init runs against bgCtx + InitLatestRootTimeout, not the caller's ctx.
	// A caller with a tight deadline must not cause init to fail for everyone.
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	// Server takes 100ms — well past the caller's 5ms deadline, but well within
	// InitLatestRootTimeout. Init must succeed.
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _ *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			time.Sleep(100 * time.Millisecond)
			return &trillian.GetLatestSignedLogRootResponse{SignedLogRoot: mkSLR(t, 7, make([]byte, 32))}, nil
		},
	).Times(1) // exactly once: init succeeds, second call hits cache

	conn := dialMock(t, s.Addr)
	cfg := DefaultConfig()
	cfg.FrozenTreeIDs = map[int64]bool{606: true} // avoid updater noise
	tc := newTrillianClient(trillian.NewTrillianLogClient(conn), 606, cfg)
	t.Cleanup(tc.Close)

	// First call: tight deadline that would have killed init under the old behavior.
	// Now init detaches to bgCtx and succeeds; caller blocks past its own deadline
	// but gets a result.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	resp := tc.GetLatest(ctx, 0)
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
	require.True(t, tc.started)

	// Second call hits the cache — no further RPC (Times(1) above enforces this).
	resp = tc.GetLatest(context.Background(), 0)
	require.NoError(t, resp.Err)
}

func TestEnsureStarted_InitTimeoutRespected(t *testing.T) {
	// InitLatestRootTimeout still bounds init when Trillian is genuinely slow.
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	// Server blocks until the init RPC's deadline fires, then returns the
	// resulting error. AnyTimes: the timeout may fire before the handler runs.
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, _ *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	).AnyTimes()

	conn := dialMock(t, s.Addr)
	cfg := DefaultConfig()
	cfg.InitLatestRootTimeout = 50 * time.Millisecond
	tc := newTrillianClient(trillian.NewTrillianLogClient(conn), 607, cfg)
	t.Cleanup(tc.Close)

	start := time.Now()
	resp := tc.GetLatest(context.Background(), 0)
	elapsed := time.Since(start)

	require.Error(t, resp.Err)
	require.Equal(t, codes.DeadlineExceeded, resp.Status)
	require.False(t, tc.started, "started must remain false on init failure so retry is possible")
	require.Less(t, elapsed, 500*time.Millisecond, "init should give up near InitLatestRootTimeout, not hang")
}

// --- New tests for channel-per-caller and edge cases ---

func TestWaitForRootAtLeast_AlreadySatisfied(t *testing.T) {
	tc := newTrillianClient(nil, 500, DefaultConfig())
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 10}})
	t.Cleanup(tc.Close)

	err := tc.waitForRootAtLeast(context.Background(), 5)
	require.NoError(t, err)

	err = tc.waitForRootAtLeast(context.Background(), 10)
	require.NoError(t, err)
}

func TestWaitForRootAtLeast_ContextCancellation(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, opt) })
	tc := newTrillianClient(nil, 501, DefaultConfig())
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}})
	t.Cleanup(tc.Close)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- tc.waitForRootAtLeast(ctx, 100)
	}()

	waitForWaiters(t, tc, 1)

	// Cancel context - should immediately unblock
	cancel()

	select {
	case err := <-done:
		require.Error(t, err)
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("waiter was not unblocked by context cancellation")
	}
}

func TestClose_UnblocksAllWaiters(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, opt) })
	tc := newTrillianClient(nil, 502, DefaultConfig())
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}})

	const numWaiters = 5
	var wg sync.WaitGroup
	wg.Add(numWaiters)
	errs := make(chan error, numWaiters)

	for i := 0; i < numWaiters; i++ {
		go func() {
			defer wg.Done()
			errs <- tc.waitForRootAtLeast(context.Background(), 999)
		}()
	}

	waitForWaiters(t, tc, numWaiters)
	tc.Close()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
		close(errs)
		for e := range errs {
			require.Error(t, e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock all waiters")
	}
}

func TestNotifyWaiters_PartialSatisfaction(t *testing.T) {
	tc := newTrillianClient(nil, 503, DefaultConfig())
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}})
	t.Cleanup(tc.Close)

	tc.mu.Lock()
	ch3 := tc.registerWaiter(3)
	ch5 := tc.registerWaiter(5)
	ch10 := tc.registerWaiter(10)
	tc.mu.Unlock()

	// Notify with size 5: should satisfy waiters for 3 and 5, but not 10
	tc.mu.Lock()
	tc.notifyWaiters(5)
	tc.mu.Unlock()

	// ch3 and ch5 should be closed (readable immediately)
	select {
	case <-ch3:
		// expected
	default:
		t.Fatal("waiter for size 3 should have been notified")
	}
	select {
	case <-ch5:
		// expected
	default:
		t.Fatal("waiter for size 5 should have been notified")
	}

	// ch10 should NOT be closed
	select {
	case <-ch10:
		t.Fatal("waiter for size 10 should NOT have been notified")
	default:
		// expected
	}

	// Verify remaining waiters count
	tc.mu.Lock()
	require.Len(t, tc.waiters, 1)
	require.Equal(t, uint64(10), tc.waiters[ch10])
	tc.mu.Unlock()
}

func TestRemoveWaiter_Cleanup(t *testing.T) {
	tc := newTrillianClient(nil, 504, DefaultConfig())
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}})
	t.Cleanup(tc.Close)

	tc.mu.Lock()
	ch1 := tc.registerWaiter(5)
	ch2 := tc.registerWaiter(10)
	require.Len(t, tc.waiters, 2)

	tc.removeWaiter(ch1)
	require.Len(t, tc.waiters, 1)
	_, ok := tc.waiters[ch2]
	require.True(t, ok)
	_, ok = tc.waiters[ch1]
	require.False(t, ok)

	// Remove non-existent channel is a no-op
	tc.removeWaiter(make(chan struct{}))
	require.Len(t, tc.waiters, 1)
	tc.mu.Unlock()
}

func TestUpdater_RetriesOnTransientErrors(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, opt) })
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	rootHash1 := bytes.Repeat([]byte{0x11}, 32)

	var latestCalls int32
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _ *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			atomic.AddInt32(&latestCalls, 1)
			return nil, status.Error(codes.Unavailable, "transient")
		},
	).AnyTimes()

	conn := dialMock(t, s.Addr)
	tc := newTrillianClient(trillian.NewTrillianLogClient(conn), 600, Config{
		UpdaterWaitTimeout: 50 * time.Millisecond,
	})
	t.Cleanup(tc.Close)

	initial := types.LogRootV1{TreeSize: 1, RootHash: rootHash1}
	tc.v = client.NewLogVerifier(rfc6962.DefaultHasher)
	tc.lc = client.New(tc.logID, tc.client, tc.v, initial)
	tc.snapshot.Store(rootSnapshot{root: initial, signed: mkSLR(t, 1, rootHash1)})

	done := make(chan struct{})
	go func() {
		tc.updater()
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&latestCalls) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	require.GreaterOrEqual(t, atomic.LoadInt32(&latestCalls), int32(2), "updater should keep retrying after transient errors")

	tc.Close()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("updater did not stop after Close")
	}
}

func TestClientManager_CachesClientPerTreeID(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	cfg := Config{CacheSTH: false}
	cm := NewClientManager(nil, GRPCConfig{Address: s.Addr, Port: 0}, cfg)

	conn := dialMock(t, s.Addr)
	cm.connMu.Lock()
	cm.connections[cm.defaultConfig] = conn
	cm.connMu.Unlock()
	t.Cleanup(func() { _ = cm.Close() })

	c1, err := cm.GetTrillianClient(7)
	require.NoError(t, err)
	c2, err := cm.GetTrillianClient(7)
	require.NoError(t, err)
	c3, err := cm.GetTrillianClient(8)
	require.NoError(t, err)

	require.Same(t, c1, c2, "same tree ID should return cached client instance")
	require.NotSame(t, c1, c3, "different tree IDs should return distinct client instances")
}

func TestClientManagerClose_ClosesClients(t *testing.T) {
	cm := NewClientManager(nil, GRPCConfig{Address: "localhost", Port: 0}, Config{})
	fake1 := &fakeCloseTrackingClient{}
	fake2 := &fakeCloseTrackingClient{}

	cm.clientMu.Lock()
	cm.trillianClients[1] = fake1
	cm.trillianClients[2] = fake2
	cm.clientMu.Unlock()

	err := cm.Close()
	require.NoError(t, err)
	require.EqualValues(t, 1, fake1.CloseCalls(), "Close should be called on cached client 1")
	require.EqualValues(t, 1, fake2.CloseCalls(), "Close should be called on cached client 2")

	cm.clientMu.RLock()
	require.True(t, cm.shutdown)
	require.Empty(t, cm.trillianClients)
	cm.clientMu.RUnlock()

	// After Close, GetTrillianClient should fail
	_, err = cm.GetTrillianClient(1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "shutting down")
}

func TestClientManagerGetConn_RejectsDialAfterClose(t *testing.T) {
	// Verify that getConn refuses to dial after Close has drained connections,
	// even if the early shutdown check passed before Close ran.
	cfg := Config{CacheSTH: false}
	cm := NewClientManager(nil, GRPCConfig{Address: "localhost", Port: 0}, cfg)

	// Close drains connections and sets shutdown.
	require.NoError(t, cm.Close())

	// getConn must reject the dial attempt despite the connections map being empty.
	_, err := cm.getConn(1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "shutting down")
}

func TestClientManagerGetConn_ConcurrentCloseNeverLeaks(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, opt) })

	cfg := Config{CacheSTH: false}
	cm := NewClientManager(nil, GRPCConfig{Address: "localhost", Port: 0}, cfg)

	// Race getConn against Close. getConn must either succeed (connection
	// stored and later cleaned up) or return a shutdown error. It must
	// never leave an orphaned connection.
	const goroutines = 20
	errs := make(chan error, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			_, err := cm.getConn(1)
			errs <- err
		}()
	}

	// Close concurrently.
	closeErr := cm.Close()
	wg.Wait()
	close(errs)

	require.NoError(t, closeErr)
	for e := range errs {
		if e != nil {
			require.Contains(t, e.Error(), "shutting down")
		}
	}

	// After Close, connections map must be empty (no leaked connections).
	cm.connMu.RLock()
	require.Empty(t, cm.connections)
	cm.connMu.RUnlock()
}

func TestClientManagerFactory_SimpleClient(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	cfg := Config{CacheSTH: false}
	cm := NewClientManager(nil, GRPCConfig{Address: s.Addr, Port: 0}, cfg)

	// Manually inject a connection since we can't dial properly in tests
	conn := dialMock(t, s.Addr)
	cm.connMu.Lock()
	cm.connections[cm.defaultConfig] = conn
	cm.connMu.Unlock()
	t.Cleanup(func() { _ = cm.Close() })

	c, err := cm.GetTrillianClient(1)
	require.NoError(t, err)
	_, ok := c.(*simpleTrillianClient)
	require.True(t, ok, "expected simpleTrillianClient when CacheSTH=false")
}

func TestClientManagerFactory_CachedClient(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	cfg := Config{
		CacheSTH:              true,
		InitLatestRootTimeout: DefaultInitLatestRootTimeout,
		UpdaterWaitTimeout:    DefaultUpdaterWaitTimeout,
	}
	cm := NewClientManager(nil, GRPCConfig{Address: s.Addr, Port: 0}, cfg)

	// Manually inject a connection
	conn := dialMock(t, s.Addr)
	cm.connMu.Lock()
	cm.connections[cm.defaultConfig] = conn
	cm.connMu.Unlock()
	t.Cleanup(func() { _ = cm.Close() })

	c, err := cm.GetTrillianClient(1)
	require.NoError(t, err)
	_, ok := c.(*TrillianClient)
	require.True(t, ok, "expected *TrillianClient when CacheSTH=true")
}

// --- Frozen tree tests ---

func TestFrozenClient_NoUpdaterStarted(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, opt) })
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	slr := mkSLR(t, 10, make([]byte, 32))
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(
		&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: slr}, nil,
	).Times(1) // Only called once during ensureStarted; no updater polling

	conn := dialMock(t, s.Addr)
	frozenCfg := DefaultConfig()
	frozenCfg.FrozenTreeIDs = map[int64]bool{700: true}
	tc := newTrillianClient(trillian.NewTrillianLogClient(conn), 700, frozenCfg)
	t.Cleanup(tc.Close)

	resp := tc.GetLatest(context.Background(), 0)
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)

	var got types.LogRootV1
	require.NoError(t, got.UnmarshalBinary(resp.GetLatestResult.SignedLogRoot.LogRoot))
	require.EqualValues(t, 10, got.TreeSize)
}

func TestFrozenClient_WaitForRootAtLeast_FailsImmediately(t *testing.T) {
	frozenCfg := DefaultConfig()
	frozenCfg.FrozenTreeIDs = map[int64]bool{701: true}
	tc := newTrillianClient(nil, 701, frozenCfg)
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 5}})
	t.Cleanup(tc.Close)

	// Request satisfied by current size
	err := tc.waitForRootAtLeast(context.Background(), 5)
	require.NoError(t, err)

	// Request above frozen size fails immediately
	err = tc.waitForRootAtLeast(context.Background(), 10)
	require.Error(t, err)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Contains(t, err.Error(), "frozen")
}

func TestClientManagerFactory_FrozenCachedClient(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	cfg := Config{
		CacheSTH:              true,
		InitLatestRootTimeout: DefaultInitLatestRootTimeout,
		UpdaterWaitTimeout:    DefaultUpdaterWaitTimeout,
		FrozenTreeIDs:         map[int64]bool{42: true},
	}
	cm := NewClientManager(nil, GRPCConfig{Address: s.Addr, Port: 0}, cfg)

	conn := dialMock(t, s.Addr)
	cm.connMu.Lock()
	cm.connections[cm.defaultConfig] = conn
	cm.connMu.Unlock()
	t.Cleanup(func() { _ = cm.Close() })

	c, err := cm.GetTrillianClient(42)
	require.NoError(t, err)
	tc, ok := c.(*TrillianClient)
	require.True(t, ok, "expected *TrillianClient when CacheSTH=true")
	require.True(t, tc.frozen, "expected frozen=true for tree in frozenTreeIDs")

	// Non-frozen tree should not be frozen
	c2, err := cm.GetTrillianClient(99)
	require.NoError(t, err)
	tc2, ok := c2.(*TrillianClient)
	require.True(t, ok)
	require.False(t, tc2.frozen, "expected frozen=false for tree not in frozenTreeIDs")
}
