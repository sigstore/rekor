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

// Package trillianclient provides Rekor wrappers around Trillian's gRPC API.
//
// Two client modes are supported:
//
//   - simpleTrillianClient (default): stateless, per-RPC behavior with no
//     background goroutines and no cached root state.
//
//   - TrillianClient (enabled with --trillian_log_server.cache_sth): cached
//     Signed Tree Head (STH) behavior with a background updater.
//
// In cached mode, the client keeps an atomic snapshot of the latest verified
// root and uses waiter channels to wake only callers whose requested tree size
// has been reached.
//
// Frozen trees (inactive shards) are identified through configuration and are
// treated specially: the client initializes once, does not start an updater,
// and fails fast when callers request sizes that cannot be reached.
//
// The package exposes metrics for updater health, root advancement, and waiting
// behavior to support operational monitoring.
//
// This package intentionally focuses on behavior and architecture. Any concrete
// latency or throughput expectations depend on deployment topology, Trillian
// configuration, and workload characteristics.
package trillianclient
