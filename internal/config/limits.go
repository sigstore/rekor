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

// Package config holds process-wide limits that rekor-server populates from
// viper at startup. These are read on hot paths, so they are plain variables
// rather than repeated viper lookups, which allocate on every call.
package config

// Zero means unlimited. rekor-server overrides these from config at startup;
// defaulting to zero preserves the unbounded behavior other callers (e.g.
// rekor-cli) get when the flags were never registered with viper.
var (
	MaxAPKMetadataSize uint64
	MaxJarMetadataSize uint64
)
