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

// Package trillianclient wraps Trillian's gRPC client with an active Signed
// Tree Head (STH) cache so read paths don't hit Trillian on every request.
//
// # Caching strategy
//
//  1. Background updater: a per-client goroutine calls
//     client.LogClient.WaitForRootUpdate, which blocks until the tree advances.
//     WaitForRootUpdate has internal exponential backoff for retryable errors.
//
//  2. Atomic snapshot: the latest observed root is stored in an atomic.Pointer
//     so read paths (GetLatest, GetLeafAndProof*) can access it without RPCs
//     or mutex contention.
//
//  3. Wait notification: a sync.Cond wakes callers blocked in
//     waitForRootAtLeast when the snapshot advances. Waiters also install a
//     watcher goroutine so caller-context cancellation broadcasts and unblocks
//     them (cond.Wait alone doesn't observe ctx.Done).
//
// # Consistency
//
//   - Read consistency: reads from a single client instance see monotonically
//     increasing tree sizes.
//
//   - Signature bytes: Trillian no longer signs the log root, so the
//     LogRootSignature/KeyHint fields on the wire message are always empty.
//     Rekor treats Trillian as an untrusted storage layer and re-signs the
//     LogRoot bytes itself; the cached SignedLogRoot only carries the
//     serialized LogRoot payload.
//
//   - Cross-client consistency: separate client instances may briefly observe
//     different tree states during rapid growth.
//
//   - Write consistency: AddLeaf blocks until an inclusion proof is available,
//     giving read-after-write for the writing client.
//
// # Availability
//
// The background updater creates a dependency on continuous Trillian
// connectivity. During an outage the cache goes stale but reads still succeed
// against the stale snapshot; AddLeaf blocks in waitForInclusionWithMinSize
// until the tree advances or the caller's context expires.
