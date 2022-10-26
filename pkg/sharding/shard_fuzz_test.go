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

import "testing"

func FuzzCreateEntryIDFromParts(f *testing.F) {
	f.Fuzz(func(t *testing.T, treeID, uuid string) {
		if _, err := CreateEntryIDFromParts(treeID, uuid); err != nil {
			t.Skipf("failed to create entryID from %v + %v: %v", treeID, uuid, err)
		}
	})
}

func FuzzGetUUIDFromIDString(f *testing.F) {
	f.Fuzz(func(t *testing.T, entryID string) {
		if _, err := GetUUIDFromIDString(entryID); err != nil {
			t.Skipf("error getting UUID from %v: %v", entryID, err)
		}
	})
}

func FuzzGetTreeIDFromIDString(f *testing.F) {
	f.Fuzz(func(t *testing.T, entryID string) {
		if _, err := GetTreeIDFromIDString(entryID); err != nil {
			t.Skipf("error getting treeID from %v: %v", entryID, err)
		}
	})
}

func FuzzPadToTreeIDLen(f *testing.F) {
	f.Fuzz(func(t *testing.T, treeID string) {
		if _, err := PadToTreeIDLen(treeID); err != nil {
			t.Skipf("error padding %v: %v", treeID, err)
		}
	})
}

func FuzzReturnEntryIDString(f *testing.F) {
	f.Fuzz(func(t *testing.T, treeID, uuid string) {
		if _, err := CreateEntryIDFromParts(treeID, uuid); err != nil {
			t.Skipf("failed to create entryID from %s + %s: %s", treeID, uuid, err)
		}
	})
}

func FuzzTreeID(f *testing.F) {
	f.Fuzz(func(t *testing.T, treeID string) {
		if _, err := TreeID(treeID); err != nil {
			t.Skipf("error creating treeID %v: %v", treeID, err)
		}
	})
}

func FuzzValidateUUID(f *testing.F) {
	f.Fuzz(func(t *testing.T, uuid string) {
		if err := ValidateUUID(uuid); err != nil {
			t.Skipf("error validating UUID %v: %v", uuid, err)
		}
	})
}

func FuzzValidateTreeID(f *testing.F) {
	f.Fuzz(func(t *testing.T, treeID string) {
		if err := ValidateTreeID(treeID); err != nil {
			t.Skipf("error validating treeID %v: %v", treeID, err)
		}
	})
}

func FuzzValidateEntryID(f *testing.F) {
	f.Fuzz(func(t *testing.T, entryID string) {
		if err := ValidateEntryID(entryID); err != nil {
			t.Skipf("error validating entryID %v: %v", entryID, err)
		}
	})
}
