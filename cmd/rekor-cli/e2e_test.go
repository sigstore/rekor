//
// Copyright 2022 The Sigstore Authors.
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

//go:build e2e

package main

import (
	"testing"

	"github.com/sigstore/rekor/pkg/util"
)

func TestGetNonExistentIndex(t *testing.T) {
	// this index is extremely likely to not exist
	out := util.RunCliErr(t, "get", "--log-index", "100000000")
	util.OutputContains(t, out, "404")
}
func TestVerifyNonExistentIndex(t *testing.T) {
	// this index is extremely likely to not exist
	out := util.RunCliErr(t, "verify", "--log-index", "100000000")
	util.OutputContains(t, out, "entry in log cannot be located")
}

func TestGetNonExistentUUID(t *testing.T) {
	// this uuid is extremely likely to not exist
	out := util.RunCliErr(t, "get", "--uuid", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	util.OutputContains(t, out, "404")
}
