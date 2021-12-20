//go:build tools
// +build tools

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
//

// This package imports things required by build scripts, to force `go mod` to see them as dependencies
package tools

import (
	_ "github.com/AdaLogics/go-fuzz-headers"
	_ "github.com/dvyukov/go-fuzz/go-fuzz"
	_ "github.com/dvyukov/go-fuzz/go-fuzz-build"
	_ "github.com/dvyukov/go-fuzz/go-fuzz-dep"
	_ "github.com/go-swagger/go-swagger/cmd/swagger"

	// These are so we can build these two binaries into containers with ko
	_ "github.com/google/trillian/cmd/trillian_log_server"
	_ "github.com/google/trillian/cmd/trillian_log_signer"
)
