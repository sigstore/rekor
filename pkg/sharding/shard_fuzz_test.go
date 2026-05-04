// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package sharding

import (
	"strings"
	"testing"
)

func FuzzCreateEntryIDFromParts(f *testing.F) {
	// Valid hex tree ID (16 chars) + valid hex UUID (64 chars)
	f.Add("0000000000000001", "a9b9c5e3f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3")
	f.Add("ffffffffffffffff", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	f.Fuzz(func(t *testing.T, treeID, uuid string) {
		e, err := CreateEntryIDFromParts(treeID, uuid)
		if err != nil {
			t.Skipf("failed to create entryID from %v + %v: %v", treeID, uuid, err)
		}
		// Round-trip: an accepted (treeID, uuid) pair must serialize to an
		// entryID string that the inverse parsers also accept and that
		// recovers the original UUID.
		idStr := e.ReturnEntryIDString()
		gotUUID, err := GetUUIDFromIDString(idStr)
		if err != nil {
			t.Fatalf("GetUUIDFromIDString rejected freshly-built entryID %q: %v", idStr, err)
		}
		if !strings.EqualFold(gotUUID, uuid) {
			t.Fatalf("UUID round-trip mismatch: in=%q out=%q", uuid, gotUUID)
		}
		if _, err := GetTreeIDFromIDString(idStr); err != nil {
			t.Fatalf("GetTreeIDFromIDString rejected freshly-built entryID %q: %v", idStr, err)
		}
	})
}

func FuzzGetUUIDFromIDString(f *testing.F) {
	// 80-char full entryID (16-char treeID + 64-char UUID)
	f.Add("0000000000000001a9b9c5e3f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3")
	// 64-char UUID-only
	f.Add("a9b9c5e3f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3")

	f.Fuzz(func(t *testing.T, entryID string) {
		if _, err := GetUUIDFromIDString(entryID); err != nil {
			t.Skipf("error getting UUID from %v: %v", entryID, err)
		}
	})
}

func FuzzGetTreeIDFromIDString(f *testing.F) {
	f.Add("0000000000000001a9b9c5e3f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3")

	f.Fuzz(func(t *testing.T, entryID string) {
		if _, err := GetTreeIDFromIDString(entryID); err != nil {
			t.Skipf("error getting treeID from %v: %v", entryID, err)
		}
	})
}

func FuzzPadToTreeIDLen(f *testing.F) {
	f.Add("1")                 // short, needs padding
	f.Add("0000000000000001")  // already correct length
	f.Add("ffffffffffffffff")  // max value
	f.Add("00000000000000001") // too long by one

	f.Fuzz(func(t *testing.T, treeID string) {
		if _, err := PadToTreeIDLen(treeID); err != nil {
			t.Skipf("error padding %v: %v", treeID, err)
		}
	})
}

func FuzzTreeID(f *testing.F) {
	f.Add("1234")
	f.Add("0")

	f.Fuzz(func(t *testing.T, treeID string) {
		if _, err := TreeID(treeID); err != nil {
			t.Skipf("error creating treeID %v: %v", treeID, err)
		}
	})
}

func FuzzValidateUUID(f *testing.F) {
	f.Add("a9b9c5e3f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3") // valid 64 hex
	f.Add("0000000000000000000000000000000000000000000000000000000000000000") // all zeros
	f.Add("AABBCCDD")                                                         // too short

	f.Fuzz(func(t *testing.T, uuid string) {
		if err := ValidateUUID(uuid); err != nil {
			t.Skipf("error validating UUID %v: %v", uuid, err)
		}
	})
}

func FuzzValidateTreeID(f *testing.F) {
	f.Add("0000000000000001") // valid
	f.Add("0000000000000000") // zero — should fail
	f.Add("ffffffffffffffff") // max

	f.Fuzz(func(t *testing.T, treeID string) {
		if err := ValidateTreeID(treeID); err != nil {
			t.Skipf("error validating treeID %v: %v", treeID, err)
		}
	})
}

func FuzzValidateEntryID(f *testing.F) {
	f.Add("0000000000000001a9b9c5e3f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3") // valid 80 hex

	f.Fuzz(func(t *testing.T, entryID string) {
		if err := ValidateEntryID(entryID); err != nil {
			t.Skipf("error validating entryID %v: %v", entryID, err)
		}
	})
}
