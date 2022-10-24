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
		_, err := CreateEntryIDFromParts(treeID, uuid)
		if err != nil {
			t.Skipf("failed to create entryID from %v + %v: %v", treeID, uuid, err)
		}
	})
}

func FuzzGetUUIDFromIDString(f *testing.F) {
	f.Fuzz(func(t *testing.T, entryID string) {
		_, err := GetUUIDFromIDString(entryID)
		if err != nil {
			t.Skipf("error getting UUID from %v: %v", entryID, err)
		}
	})
}

func FuzzGetTreeIDFromIDString(f *testing.F) {
	f.Fuzz(func(t *testing.T, entryID string) {
		_, err := GetTreeIDFromIDString(entryID)
		if err != nil {
			t.Skipf("error getting treeID from %v: %v", entryID, err)
		}
	})
}

func FuzzPadToTreeIDLen(f *testing.F) {
	f.Fuzz(func(t *testing.T, treeID string) {
		_, err := PadToTreeIDLen(treeID)
		if err != nil {
			t.Skipf("error padding %v: %v", treeID, err)
		}
	})
}

func FuzzReturnEntryIDString(f *testing.F) {
	f.Fuzz(func(t *testing.T, treeID, uuid string) {
		_, err := CreateEntryIDFromParts(treeID, uuid)
		if err != nil {
			t.Skipf("failed to create entryID from %s + %s: %s", treeID, uuid, err)
		}
	})
}

func FuzzTreeID(f *testing.F) {
	f.Fuzz(func(t *testing.T, treeID string) {
		_, err := TreeID(treeID)
		if err != nil {
			t.Skipf("error creating treeID %v: %v", treeID, err)
		}
	})
}

func FuzzValidateUUID(f *testing.F) {
	f.Fuzz(func(t *testing.T, uuid string) {
		err := ValidateUUID(uuid)
		if err != nil {
			t.Skipf("error validating UUID %v: %v", uuid, err)
		}
	})
}

func FuzzValidateTreeID(f *testing.F) {
	f.Fuzz(func(t *testing.T, treeID string) {
		err := ValidateTreeID(treeID)
		if err != nil {
			t.Skipf("error validating treeID %v: %v", treeID, err)
		}
	})
}

func FuzzValidateEntryID(f *testing.F) {
	f.Fuzz(func(t *testing.T, entryID string) {
		err := ValidateEntryID(entryID)
		if err != nil {
			t.Skipf("error validating entryID %v: %v", entryID, err)
		}
	})
}
