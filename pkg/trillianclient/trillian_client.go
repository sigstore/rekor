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
	"github.com/google/trillian/client/backoff"
	"github.com/google/trillian/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sigstore/rekor/pkg/log"
)

// Default timeouts for initialization and updater polling.
// These can be overridden via TrillianClientConfig.
const (
	DefaultInitLatestRootTimeout = 3 * time.Second
	DefaultUpdaterWaitTimeout    = 3 * time.Second
)

var (
	metricRootAdvance = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rekor_trillian_root_advance_total",
			Help: "Number of root advances observed by the Trillian client.",
		},
		[]string{"tree"},
	)
	metricUpdaterErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rekor_trillian_updater_errors_total",
			Help: "Total updater errors (wait/fetch/marshal).",
		},
		[]string{"tree"},
	)
	metricLatestTreeSize = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rekor_trillian_latest_tree_size",
			Help: "Latest observed tree size per tree.",
		},
		[]string{"tree"},
	)
	metricWaitForRootAtLeast = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "rekor_trillian_wait_for_root_ms",
			Help:    "Time spent waiting for the root to reach at least a given size (ms).",
			Buckets: prometheus.ExponentialBuckets(1, 2, 12),
		},
		[]string{"tree", "success"},
	)
	metricInclusionWait = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "rekor_trillian_inclusion_wait_ms",
			Help:    "Time to obtain an inclusion proof (ms).",
			Buckets: prometheus.ExponentialBuckets(1, 2, 12),
		},
		[]string{"success"},
	)
)

func init() {
	// Register metrics once.
	prometheus.MustRegister(
		metricRootAdvance,
		metricUpdaterErrors,
		metricLatestTreeSize,
		metricWaitForRootAtLeast,
		metricInclusionWait,
	)
}

// Config holds configuration options for TrillianClient
type Config struct {
	// InitLatestRootTimeout is the timeout for fetching the latest root during initialization
	InitLatestRootTimeout time.Duration
	// UpdaterWaitTimeout is the timeout for updater polling wait operations
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
	snapshot atomic.Value // stores rootSnapshot

	// lifecycle
	started  bool
	startErr error
	stopCh   chan struct{}

	// bgCtx is canceled on Close to interrupt long waits in the updater.
	bgCtx    context.Context
	bgCancel context.CancelFunc
}

type rootSnapshot struct {
	root   types.LogRootV1
	signed *trillian.SignedLogRoot
}

// newTrillianClient creates a TrillianClient with the given Trillian client, log/tree ID, and config.
func newTrillianClient(logClient trillian.TrillianLogClient, logID int64, config Config) *TrillianClient {
	t := &TrillianClient{
		client: logClient,
		logID:  logID,
		config: config,
		stopCh: make(chan struct{}),
	}
	t.bgCtx, t.bgCancel = context.WithCancel(context.Background())
	t.cond = sync.NewCond(&t.mu)
	// initialize atomic snapshot with zero value
	t.snapshot.Store(rootSnapshot{})
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

// ensureStarted initializes the shared LogClient and starts the updater once.
//
// Locking strategy: this uses a double-checked initialization gate so network
// calls do not hold the mutex. Only one goroutine performs the initial RPCs,
// others wait on the condition variable until initialization completes. This
// avoids head-of-line blocking while keeping state updates atomic.
func (t *TrillianClient) ensureStarted(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.started {
		return t.startErr
	}

	// Perform one-time initialization while holding the lock for simplicity.
	// This blocks other ensureStarted callers until initialization completes.
	cctx := ctx
	var cancel context.CancelFunc
	if _, ok := ctx.Deadline(); !ok {
		cctx, cancel = context.WithTimeout(ctx, t.config.InitLatestRootTimeout)
	}
	if cancel != nil {
		defer cancel()
	}
	slr, err := t.client.GetLatestSignedLogRoot(cctx, &trillian.GetLatestSignedLogRootRequest{LogId: t.logID})
	if err != nil {
		t.startErr = err
		return err
	}
	if slr == nil || slr.SignedLogRoot == nil {
		err = fmt.Errorf("nil signed log root")
		t.startErr = err
		return err
	}
	r, uerr := unmarshalLogRoot(slr.SignedLogRoot.LogRoot)
	if uerr != nil {
		t.startErr = uerr
		return uerr
	}

	t.v = client.NewLogVerifier(rfc6962.DefaultHasher)
	t.lc = client.New(t.logID, t.client, t.v, r)
	t.snapshot.Store(rootSnapshot{root: r, signed: slr.SignedLogRoot})
	t.started = true
	t.startErr = nil

	// Start updater and track it for graceful shutdown.
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		t.updater()
	}()
	return nil
}

// updater waits for root changes using the LogClient and notifies waiters.
// It uses the parsed root from WaitForRootUpdate and synthesizes a minimal
// SignedLogRoot (LogRoot bytes only) to avoid an extra network round trip
// per advancement.
func (t *TrillianClient) updater() {
	// Create backoff for retry logic with reasonable defaults
	bo := backoff.Backoff{
		Min:    100 * time.Millisecond, // Start with 100ms
		Max:    30 * time.Second,       // Cap at 30s
		Factor: 2.0,                    // Double each time
		Jitter: true,                   // Add randomization
	}
	for {
		// Wrap the WaitForRootUpdate call with backoff retry
		var nr *types.LogRootV1
		err := bo.Retry(t.bgCtx, func() error {
			select {
			case <-t.stopCh:
				return fmt.Errorf("client stopped")
			default:
			}

			ctx, cancel := context.WithTimeout(t.bgCtx, t.config.UpdaterWaitTimeout)
			defer cancel()

			var waitErr error
			nr, waitErr = t.lc.WaitForRootUpdate(ctx)
			return waitErr
		})
		select {
		case <-t.stopCh:
			return
		default:
		}

		if err != nil {
			log.Logger.Debugw("trillian root update wait failed after retries", "treeID", t.logID, "err", err)
			metricUpdaterErrors.WithLabelValues(fmt.Sprintf("%d", t.logID)).Inc()
			// Reset backoff on persistent failure and continue to next iteration
			bo.Reset()
			continue
		}

		// Success - reset backoff for next potential failure
		bo.Reset()

		if nr == nil {
			continue
		}

		// compute change against current snapshot
		old := t.snapshot.Load().(rootSnapshot)
		changed := nr.TreeSize != old.root.TreeSize || !bytes.Equal(nr.RootHash, old.root.RootHash)
		if !changed {
			// nothing to publish
			continue
		}
		log.Logger.Debugw("trillian root advanced", "treeID", t.logID, "oldSize", old.root.TreeSize, "newSize", nr.TreeSize)

		// Marshal parsed root to bytes and synthesize a minimal SignedLogRoot
		lrBytes, mErr := nr.MarshalBinary()
		if mErr != nil {
			log.Logger.Debugw("failed to marshal updated log root", "treeID", t.logID, "err", mErr)
			metricUpdaterErrors.WithLabelValues(fmt.Sprintf("%d", t.logID)).Inc()
			continue
		}
		slr := &trillian.SignedLogRoot{LogRoot: lrBytes}

		// publish new snapshot and notify waiters
		t.mu.Lock()
		t.snapshot.Store(rootSnapshot{root: *nr, signed: slr})
		t.cond.Broadcast()
		t.mu.Unlock()

		// metrics
		tree := fmt.Sprintf("%d", t.logID)
		metricRootAdvance.WithLabelValues(tree).Inc()
		metricLatestTreeSize.WithLabelValues(tree).Set(float64(nr.TreeSize))
	}
}

// Close stops the updater.
func (t *TrillianClient) Close() {
	t.mu.Lock()
	// Cancel background operations first to unblock any waits
	if t.bgCancel != nil {
		t.bgCancel()
	}
	select {
	case <-t.stopCh:
	default:
		close(t.stopCh)
	}
	// Wake waiters so they can observe shutdown via context or state
	t.cond.Broadcast()
	t.mu.Unlock()
	// Wait for updater to exit
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
	preSnap, _ := t.snapshot.Load().(rootSnapshot)
	baselineSize := preSnap.root.TreeSize
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
	snap, _ := t.snapshot.Load().(rootSnapshot)
	root := snap.root
	signed := snap.signed
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
	snap, _ := t.snapshot.Load().(rootSnapshot)
	root := snap.root
	signed := snap.signed

	resp, err := t.client.GetEntryAndProof(ctx, &trillian.GetEntryAndProofRequest{
		LogId:     t.logID,
		LeafIndex: index,
		TreeSize:  int64(root.TreeSize),
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
	snap, _ := t.snapshot.Load().(rootSnapshot)
	signed := snap.signed
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
	resp, err := t.client.GetInclusionProofByHash(ctx, &trillian.GetInclusionProofByHashRequest{
		LogId:    t.logID,
		LeafHash: hashValue,
		TreeSize: int64(root.TreeSize),
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
	start := time.Now()

	// Optionally delay the very first attempt until minSize is reached.
	// If the current snapshot is already beyond minSize, this returns immediately.
	if err := t.waitForRootAtLeast(ctx, minSize); err != nil {
		elapsed := float64(time.Since(start).Milliseconds())
		metricInclusionWait.WithLabelValues("false").Observe(elapsed)
		return &Response{Status: status.Code(err), Err: err}
	}

	for {
		if err := ctx.Err(); err != nil {
			elapsed := float64(time.Since(start).Milliseconds())
			metricInclusionWait.WithLabelValues("false").Observe(elapsed)
			return &Response{Status: status.Code(err), Err: err}
		}
		snap, _ := t.snapshot.Load().(rootSnapshot)
		root := snap.root
		signed := snap.signed

		proofResp := t.getProofByHashWithRoot(ctx, leafHash, root, signed)
		if proofResp.Err == nil || status.Code(proofResp.Err) != codes.NotFound {
			success := proofResp.Err == nil
			elapsed := float64(time.Since(start).Milliseconds())
			metricInclusionWait.WithLabelValues(fmt.Sprintf("%t", success)).Observe(elapsed)
			return proofResp
		}

		// NotFound: wait for the tree to grow and try again
		if err := t.waitForRootAtLeast(ctx, root.TreeSize+1); err != nil {
			return &Response{Status: status.Code(err), Err: err}
		}
	}
}

// waitForRootAtLeast blocks until t.lastRoot.TreeSize >= size, or context/client closes.
func (t *TrillianClient) waitForRootAtLeast(ctx context.Context, size uint64) error {
	start := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			// metrics
			elapsed := float64(time.Since(start).Milliseconds())
			metricWaitForRootAtLeast.WithLabelValues(fmt.Sprintf("%d", t.logID), "false").Observe(elapsed)
			return err
		}
		select {
		case <-t.stopCh:
			elapsed := float64(time.Since(start).Milliseconds())
			metricWaitForRootAtLeast.WithLabelValues(fmt.Sprintf("%d", t.logID), "false").Observe(elapsed)
			return status.Error(codes.Canceled, "client closed")
		default:
		}
		cur := t.snapshot.Load().(rootSnapshot)
		if cur.root.TreeSize >= size {
			elapsed := float64(time.Since(start).Milliseconds())
			metricWaitForRootAtLeast.WithLabelValues(fmt.Sprintf("%d", t.logID), "true").Observe(elapsed)
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
