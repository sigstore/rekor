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

package tle

import (
	"encoding/base64"
	"testing"

	fuzz "github.com/AdamKorcz/go-fuzz-headers-1"

	"github.com/sigstore/rekor/pkg/generated/models"
	_ "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
)

// FuzzGenerateTransparencyLogEntry exercises the LogEntryAnon -> protobuf TLE
// conversion that clients use on responses from the log. The function performs
// many pointer dereferences, hex/base64 decodes, and a nested ProposedEntry
// unmarshal; any panic here is reachable from a malicious or malformed server
// response.
func FuzzGenerateTransparencyLogEntry(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, bodyAsString bool) {
		ff := fuzz.NewConsumer(data)

		anon := models.LogEntryAnon{}
		if err := ff.GenerateStruct(&anon); err != nil {
			t.Skip()
		}
		// GenerateStruct allocates nested *struct fields but leaves the `any`
		// Body unset; supply it explicitly so the fuzzer reaches
		// UnmarshalProposedEntry / types.UnmarshalEntry.
		bodyBytes, err := ff.GetBytes()
		if err != nil {
			t.Skip()
		}
		if bodyAsString {
			anon.Body = base64.StdEncoding.EncodeToString(bodyBytes)
		} else {
			anon.Body = bodyBytes
		}
		// GenerateStruct may leave required pointer fields nil when it runs
		// out of data; the function's documented contract assumes a validated
		// swagger response, so skip incomplete inputs and let the mutator
		// vary the leaf values (hex strings, hashes, indices).
		if anon.LogID == nil || anon.LogIndex == nil || anon.IntegratedTime == nil ||
			anon.Verification == nil || anon.Verification.InclusionProof == nil {
			t.Skip()
		}
		ip := anon.Verification.InclusionProof
		if ip.RootHash == nil || ip.LogIndex == nil || ip.TreeSize == nil || ip.Checkpoint == nil {
			t.Skip()
		}

		tle, err := GenerateTransparencyLogEntry(anon)
		if err != nil {
			return
		}
		if _, err := MarshalTLEToJSON(tle); err != nil {
			t.Fatalf("generated TLE failed to marshal: %v", err)
		}
	})
}
