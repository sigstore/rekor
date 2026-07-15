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
	"sync"
	"sync/atomic"
	"time"

	"github.com/transparency-dev/merkle/rfc6962"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/types"
	"github.com/sigstore/rekor/pkg/log"
)

const (
	DefaultInitLatestRootTimeout = 3 * time.Second
	DefaultUpdaterWaitTimeout    = 3 * time.Second

	// updaterMinErrorBackoff and updaterMaxErrorBackoff bound the exponential
	// sleep between updater retries on non-retryable errors returned by
	// WaitForRootUpdate. WaitForRootUpdate retries Unavailable/NotFound/
	// FailedPrecondition itself; all other error codes propagate up and would
	// otherwise spin the loop at RPC-completion rate.
	updaterMinErrorBackoff = 100 * time.Millisecond
	updaterMaxErrorBackoff = 30 * time.Second
)

// Config holds configuration options for TrillianClient
type Config struct {
	// InitLatestRootTimeout is the timeout for fetching the latest root during initialization
	InitLatestRootTimeout time.Duration
	// UpdaterWaitTimeout bounds each WaitForRootUpdate call so the updater
	// periodically wakes to observe shutdown; DeadlineExceeded from this timeout
	// is treated as normal on a quiet tree, not an error.
	UpdaterWaitTimeout time.Duration
}

// DefaultConfig returns a config with default timeout values
func DefaultConfig() Config {
	return Config{
		InitLatestRootTimeout: DefaultInitLatestRootTimeout,
		UpdaterWaitTimeout:    DefaultUpdaterWaitTimeout,
	}
}

// TrillianClient provides a wrapper around the Trillian client
type TrillianClient struct {
	client trillian.TrillianLogClient
	logID  int64
	config Config

	// shared trillian client/verifier
	lc   *client.LogClient
	v    *client.LogVerifier
	mu   sync.Mutex
	cond *sync.Cond
	wg   sync.WaitGroup

	// cached root snapshot (atomic for read-heavy paths)
	snapshot atomic.Pointer[rootSnapshot]

	// started is atomic so read paths can fast-path past the mutex;
	// only the first successful ensureStarted transitions it to true, and all
	// initialization state (lc, v, snapshot) is published before that store.
	started atomic.Bool

	// bgCtx is canceled on Close to interrupt long waits in the updater and
	// wake blocked waiters in waitForRootAtLeast.
	bgCtx    context.Context
	bgCancel context.CancelFunc
}

type rootSnapshot struct {
	root types.LogRootV1
	// serialized holds the LogRoot bytes for the current snapshot.
	// Trillian no longer acts as a trust boundary, so this never contains a signature.
	serialized *trillian.SignedLogRoot
}

// newTrillianClient creates a TrillianClient with the given Trillian client, log/tree ID, and config.
func newTrillianClient(logClient trillian.TrillianLogClient, logID int64, config Config) *TrillianClient {
	t := &TrillianClient{
		client: logClient,
		logID:  logID,
		config: config,
	}
	t.bgCtx, t.bgCancel = context.WithCancel(context.Background())
	t.cond = sync.NewCond(&t.mu)
	t.snapshot.Store(&rootSnapshot{})
	return t
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

// ensureStarted performs one-time initialization of the shared LogClient and
// starts the updater goroutine. The fast path is a single atomic load; the
// cold path takes t.mu so concurrent first-callers serialize on initialization.
// A failed init leaves started=false so the next caller retries.
func (t *TrillianClient) ensureStarted(ctx context.Context) error {
	if t.started.Load() {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.started.Load() {
		return nil
	}
	if err := t.bgCtx.Err(); err != nil {
		return status.Error(codes.Canceled, "client closed")
	}

	// If the caller already supplied a deadline, honor it; otherwise cap
	// initialization at InitLatestRootTimeout so a stuck Trillian can't wedge
	// startup.
	cctx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		cctx, cancel = context.WithTimeout(ctx, t.config.InitLatestRootTimeout)
		defer cancel()
	}
	// Ensure Close() can interrupt an in-flight init RPC via bgCtx cancellation
	// even though we hold t.mu here.
	cctx, cancelOnClose := context.WithCancel(cctx)
	defer cancelOnClose()
	defer context.AfterFunc(t.bgCtx, cancelOnClose)()
	slr, err := t.client.GetLatestSignedLogRoot(cctx, &trillian.GetLatestSignedLogRootRequest{LogId: t.logID})
	if err != nil {
		return err
	}
	if slr == nil || slr.SignedLogRoot == nil {
		return fmt.Errorf("nil signed log root")
	}
	r, err := unmarshalLogRoot(slr.SignedLogRoot.LogRoot)
	if err != nil {
		return err
	}

	t.v = client.NewLogVerifier(rfc6962.DefaultHasher)
	t.lc = client.New(t.logID, t.client, t.v, r)
	t.snapshot.Store(&rootSnapshot{root: r, serialized: slr.SignedLogRoot})
	// Publish started only after all init state is committed so lock-free
	// readers on the fast path never see a partially initialized client.
	t.started.Store(true)

	t.wg.Go(t.updater)
	return nil
}

// updater waits for root changes using the LogClient and notifies waiters.
// Each WaitForRootUpdate call is bounded by UpdaterWaitTimeout so shutdown is
// observed promptly; DeadlineExceeded from that timeout is normal on a quiet
// tree, not a failure. The parsed root is re-marshaled into a synthetic
// SignedLogRoot to avoid an extra GetLatestSignedLogRoot RPC per advancement.
func (t *TrillianClient) updater() {
	errBackoff := updaterMinErrorBackoff
	for {
		if t.bgCtx.Err() != nil {
			return
		}

		ctx, cancel := context.WithTimeout(t.bgCtx, t.config.UpdaterWaitTimeout)
		nr, err := t.lc.WaitForRootUpdate(ctx)
		cancel()

		if t.bgCtx.Err() != nil {
			return
		}
		if err != nil {
			if status.Code(err) != codes.DeadlineExceeded {
				log.Logger.Debugw("trillian root update wait failed", "treeID", t.logID, "err", err, "backoff", errBackoff)
				timer := time.NewTimer(errBackoff)
				select {
				case <-t.bgCtx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
				if errBackoff *= 2; errBackoff > updaterMaxErrorBackoff {
					errBackoff = updaterMaxErrorBackoff
				}
			}
			continue
		}
		errBackoff = updaterMinErrorBackoff

		if nr == nil {
			continue
		}

		old := t.snapshot.Load()
		if nr.TreeSize == old.root.TreeSize && bytes.Equal(nr.RootHash, old.root.RootHash) {
			continue
		}
		log.Logger.Debugw("trillian root advanced", "treeID", t.logID, "oldSize", old.root.TreeSize, "newSize", nr.TreeSize)

		lrBytes, mErr := nr.MarshalBinary()
		if mErr != nil {
			log.Logger.Debugw("failed to marshal updated log root", "treeID", t.logID, "err", mErr)
			continue
		}

		t.mu.Lock()
		t.snapshot.Store(&rootSnapshot{root: *nr, serialized: &trillian.SignedLogRoot{LogRoot: lrBytes}})
		t.cond.Broadcast()
		t.mu.Unlock()
	}
}

// Close stops the updater and wakes any blocked waiters so they can observe
// shutdown via bgCtx.
func (t *TrillianClient) Close() {
	// Cancel bgCtx before taking t.mu: an in-flight ensureStarted holds t.mu
	// across its GetLatestSignedLogRoot RPC, and that RPC's context is tied to
	// bgCtx via AfterFunc so this cancel unblocks it.
	t.bgCancel()
	t.mu.Lock()
	t.cond.Broadcast()
	t.mu.Unlock()
	t.wg.Wait()
}

func (t *TrillianClient) AddLeaf(ctx context.Context, byteValue []byte) *Response {
	if err := t.ensureStarted(ctx); err != nil {
		return &Response{
			Status: status.Code(err),
			Err:    err,
		}
	}
	// Capture baseline tree size before queueing to set the first gate correctly.
	baselineSize := t.snapshot.Load().root.TreeSize
	leaf := &trillian.LogLeaf{
		LeafValue: byteValue,
	}
	rqst := &trillian.QueueLeafRequest{
		LogId: t.logID,
		Leaf:  leaf,
	}
	resp, err := t.client.QueueLeaf(ctx, rqst)
	if err != nil || (resp.QueuedLeaf.Status != nil && resp.QueuedLeaf.Status.Code != int32(codes.OK)) {
		return &Response{
			Status:       status.Code(err),
			Err:          err,
			GetAddResult: resp,
		}
	}

	// Gate the first proof attempt on the next root advance relative to the
	// snapshot observed here. This avoids an almost-always NotFound on the
	// very first try and trims unnecessary RPCs without impacting latency
	// (we need a root advance to include the leaf anyway).
	minSize := baselineSize + 1
	proofResp := t.waitForInclusionWithMinSize(ctx, resp.QueuedLeaf.Leaf.MerkleLeafHash, minSize)
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
	if err := t.ensureStarted(ctx); err != nil {
		return &Response{
			Status: status.Code(err),
			Err:    err,
		}
	}
	snap := t.snapshot.Load()
	root := snap.root
	signed := snap.serialized
	proofResp := t.getProofByHashWithRoot(ctx, hash, root, signed)
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
	if err := t.ensureStarted(ctx); err != nil {
		return &Response{
			Status: status.Code(err),
			Err:    err,
		}
	}
	snap := t.snapshot.Load()
	root := snap.root
	signed := snap.serialized

	resp, err := t.client.GetEntryAndProof(ctx,
		&trillian.GetEntryAndProofRequest{
			LogId:     t.logID,
			LeafIndex: index,
			TreeSize:  int64(root.TreeSize), //nolint:gosec
		})
	if err != nil {
		return &Response{
			Status: status.Code(err),
			Err:    err,
		}
	}

	if resp != nil && resp.Proof != nil {
		if err := t.v.VerifyInclusionByHash(&root, resp.GetLeaf().MerkleLeafHash, resp.Proof); err != nil {
			return &Response{
				Status: status.Code(err),
				Err:    err,
			}
		}
		return &Response{
			Status: codes.OK,
			GetLeafAndProofResult: &trillian.GetEntryAndProofResponse{
				Proof:         resp.Proof,
				Leaf:          resp.Leaf,
				SignedLogRoot: signed,
			},
		}
	}
	return &Response{
		Status: codes.NotFound,
		Err:    fmt.Errorf("trillian returned empty response for index %d", index),
	}
}

func (t *TrillianClient) GetLatest(ctx context.Context, firstSize int64) *Response {
	if err := t.ensureStarted(ctx); err != nil {
		return &Response{
			Status: status.Code(err),
			Err:    err,
		}
	}
	if firstSize > 0 {
		if err := t.waitForRootAtLeast(ctx, uint64(firstSize)); err != nil {
			return &Response{
				Status: status.Code(err),
				Err:    err,
			}
		}
	}
	snap := t.snapshot.Load()
	signed := snap.serialized
	if signed == nil {
		return &Response{
			Status: codes.NotFound,
			Err:    status.Error(codes.NotFound, "no signed root available"),
		}
	}
	return &Response{
		Status: codes.OK,
		GetLatestResult: &trillian.GetLatestSignedLogRootResponse{
			SignedLogRoot: signed,
		},
	}
}

func (t *TrillianClient) GetConsistencyProof(ctx context.Context, firstSize, lastSize int64) *Response {
	resp, err := t.client.GetConsistencyProof(ctx, &trillian.GetConsistencyProofRequest{
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

func (t *TrillianClient) getProofByHashWithRoot(ctx context.Context, hashValue []byte, root types.LogRootV1, signed *trillian.SignedLogRoot) *Response {
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
			TreeSize: int64(root.TreeSize), //nolint:gosec
		})
	if err != nil {
		return &Response{
			Status: status.Code(err),
			Err:    err,
		}
	}
	if resp != nil {
		for _, p := range resp.Proof {
			if err := t.v.VerifyInclusionByHash(&root, hashValue, p); err != nil {
				return &Response{
					Status: status.Code(err),
					Err:    err,
				}
			}
		}
		return &Response{
			Status: codes.OK,
			getProofResult: &trillian.GetInclusionProofByHashResponse{
				Proof:         resp.Proof,
				SignedLogRoot: signed,
			},
		}
	}
	return &Response{
		Status: codes.Unknown,
		Err:    fmt.Errorf("trillian returned empty proof for hash %s", hex.EncodeToString(hashValue)),
	}
}

// waitForInclusionWithMinSize behaves like waitForInclusion but ensures the
// first inclusion-proof attempt happens only after the tree has reached at
// least minSize. This reduces initial NotFound churn without increasing time
// to success (since inclusion requires a root advance).
func (t *TrillianClient) waitForInclusionWithMinSize(ctx context.Context, leafHash []byte, minSize uint64) *Response {
	// Optionally delay the very first attempt until minSize is reached.
	// If the current snapshot is already beyond minSize, this returns immediately.
	if err := t.waitForRootAtLeast(ctx, minSize); err != nil {
		return &Response{Status: status.Code(err), Err: err}
	}

	for {
		if err := ctx.Err(); err != nil {
			return &Response{Status: status.Code(err), Err: err}
		}
		snap := t.snapshot.Load()
		root := snap.root
		signed := snap.serialized

		proofResp := t.getProofByHashWithRoot(ctx, leafHash, root, signed)
		if proofResp.Err == nil || status.Code(proofResp.Err) != codes.NotFound {
			return proofResp
		}

		// NotFound: wait for the tree to grow and try again
		if err := t.waitForRootAtLeast(ctx, root.TreeSize+1); err != nil {
			return &Response{Status: status.Code(err), Err: err}
		}
	}
}

// waitForRootAtLeast blocks until the cached tree size >= size, or the caller
// context expires, or the client closes. Fast path avoids the mutex when the
// snapshot already satisfies the requirement.
func (t *TrillianClient) waitForRootAtLeast(ctx context.Context, size uint64) error {
	if t.snapshot.Load().root.TreeSize >= size {
		return nil
	}

	// cond.Wait only wakes on Broadcast, so caller-context cancellation would
	// leave this goroutine parked until the next tree advance. AfterFunc fires
	// a Broadcast when ctx is canceled; the returned stop() is called on return
	// so a still-live ctx doesn't spawn a broadcast after we've left.
	stop := context.AfterFunc(ctx, func() {
		t.mu.Lock()
		t.cond.Broadcast()
		t.mu.Unlock()
	})
	defer stop()

	t.mu.Lock()
	defer t.mu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := t.bgCtx.Err(); err != nil {
			return status.Error(codes.Canceled, "client closed")
		}
		if t.snapshot.Load().root.TreeSize >= size {
			return nil
		}
		t.cond.Wait()
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
