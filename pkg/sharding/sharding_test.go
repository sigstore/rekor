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

package sharding

import (
	"strconv"
	"testing"
)

// Create some test data
// Good data
const validTreeID1 = "FFFFFFFFFFFFFFFF"
const validTreeID2 = "0000000000000000"
const validTreeID3 = "7241b7903737211c"
const shortTreeID = "12345"

const validUUID = "f794467401d57241b7903737211c721cb3315648d077a9f02ceefb6e404a05de"

const validEntryID1 = validTreeID1 + validUUID
const validEntryID2 = validTreeID2 + validUUID
const validEntryID3 = validTreeID3 + validUUID

var validTreeIDs = []string{validTreeID1, validTreeID2, validTreeID3, shortTreeID}
var validEntryIDs = []string{validEntryID1, validEntryID2, validEntryID3}

// Bad data
// Wrong length
const tooLongTreeID = validTreeID1 + "e"

const tooLongUUID = validUUID + "e"

var tooShortUUID = validUUID[:len(validUUID)-1]

const tooLongEntryID = validEntryID1 + "e"

var tooShortEntryID = validEntryID1[:len(validEntryID1)-1]

var wrongLengthTreeIDs = []string{tooLongTreeID, validEntryID3, validUUID}
var wrongLengthUUIDs = []string{tooShortUUID, tooLongUUID, validEntryID3, validTreeID1}
var wrongLengthEntryandUUIDs = []string{tooLongEntryID, tooShortEntryID, tooLongUUID, tooShortUUID, validTreeID3}

// Not valid hex
const notHexTreeID1 = "ZZZZZZZZZZZZZZZZ"
const notHexTreeID2 = "FFFFFFF_FFFFFFFF"
const notHexTreeID3 = "xxFFFFFFFFFFFFFF"

const notHexUUID1 = "94467401d57241b7903737211c721cb3315648d077a9f02ceefb6e404a05dezq"
const notHexUUID2 = "y794467401d57241b7903737211c721cb3315648d077a9f02ceefb6e404a05de"
const notHexUUID3 = "f794467401d57241b7903737211c721cbp3315648d077a9f02ceefb6e404a05d"

const notHexEntryID1 = notHexTreeID1 + validUUID
const notHexEntryID2 = validTreeID2 + notHexUUID1
const notHexEntryID3 = notHexTreeID2 + notHexUUID3

var notHexTreeIDs = []string{notHexTreeID1, notHexTreeID2, notHexTreeID3}
var notHexUUIDs = []string{notHexUUID1, notHexUUID2, notHexUUID3}
var notHexEntryandUUIDs = []string{notHexEntryID1, notHexEntryID2, notHexEntryID3, notHexUUID1, notHexUUID2, notHexUUID3}

// Test functions
func TestCreateEntryID(t *testing.T) {
	for _, s := range wrongLengthTreeIDs {
		if _, err := CreateEntryIDFromParts(s, validUUID); err == nil {
			t.Errorf("expected length error for wrong TreeID of invalid len: %v", s)
		}
	}

	for _, s := range wrongLengthUUIDs {
		if _, err := CreateEntryIDFromParts(validTreeID1, s); err == nil {
			t.Errorf("expected length error for wrong UUID of invalid len: %v", s)
		}
	}

	for _, s := range notHexTreeIDs {
		if _, err := CreateEntryIDFromParts(s, validUUID); err == nil {
			t.Errorf("expected hex error for TreeID: %v", s)
		}
	}
	for _, s := range notHexUUIDs {
		if _, err := CreateEntryIDFromParts(validTreeID3, s); err == nil {
			t.Errorf("expected hex error for UUID: %v", s)
		}
	}

	for _, tid := range validTreeIDs {
		entryID, err := CreateEntryIDFromParts(tid, validUUID)
		if err != nil {
			t.Errorf("failed to create entryID from %v + %v: %v", tid, validUUID, err)
		}

		expectedTid, _ := PadToTreeIDLen(tid)
		if entryID.TreeID != expectedTid {
			t.Errorf("created entryID with incorrect treeID: expected %v, got %v", tid, entryID.TreeID)
		}

		if entryID.UUID != validUUID {
			t.Errorf("created entryID with incorrect UUID: expected %v, got %v", validUUID, entryID.UUID)
		}
	}

}

func TestCreateEmptyEntryID(t *testing.T) {
	emptyEntryID := createEmptyEntryID()

	if emptyEntryID.TreeID != "" {
		t.Errorf("expected empty EntryID.TreeID but got %v", emptyEntryID.TreeID)
	}

	if emptyEntryID.UUID != "" {
		t.Errorf("expected empty EntryID.UUID but got %v", emptyEntryID.UUID)
	}
}

func TestCreateEntryIDWithActiveTreeID(t *testing.T) {
	entryID, err := CreateEntryIDWithActiveTreeID(validUUID)
	if err != nil {
		t.Errorf("unable to create entryID: %v", err)
	}

	// TODO: Update dummy to be the global LogRanges struct
	activeIndexString := strconv.FormatUint(dummyLogRanges.ActiveIndex(), 10)
	expectedTreeID, err := PadToTreeIDLen(activeIndexString)
	if err != nil {
		t.Errorf("unable to pad %v to treeIDLen: %v", activeIndexString, err)
	}
	if entryID.TreeID != expectedTreeID {
		t.Errorf("expected entryID.TreeID %v but got %v", dummyLogRanges.ActiveIndex(), entryID.TreeID)
	}

	if entryID.UUID != validUUID {
		t.Errorf("expected entryID.TreeID %v but got %v", validUUID, entryID.UUID)
	}
}

func TestPadToTreeIDLen(t *testing.T) {
	short := "12345678"
	shortPadded := "0000000012345678"
	medium := "1234567812345678"
	long := "12345678901234567890"

	result1, err1 := PadToTreeIDLen(short)
	if result1 != shortPadded || err1 != nil {
		t.Errorf("error padding %v: expected (%v, nil), got (%v, %v)", short, shortPadded, result1, err1)
	}

	result2, err2 := PadToTreeIDLen(medium)
	if result2 != medium || err2 != nil {
		t.Errorf("error padding %v: expected (%v, nil), got (%v, %v)", medium, medium, result2, err2)
	}

	result3, err3 := PadToTreeIDLen(long)
	if result3 != "" || err3 == nil {
		t.Errorf("expected error in padding %v, but got %v", long, result3)
	}
}

func TestReturnEntryIDString(t *testing.T) {
	entryID, _ := CreateEntryIDFromParts(validTreeID1, validUUID)

	IDString := entryID.ReturnEntryIDString()

	if IDString != validEntryID1 {
		t.Errorf("expected entryID string %v but got %v", validEntryID1, IDString)
	}
}

func TestGetUUIDFromIDString(t *testing.T) {
	for _, s := range wrongLengthEntryandUUIDs {
		// TODO: check for correct error
		if _, err := GetUUIDFromIDString(s); err == nil {
			t.Errorf("expected length error for GetUUIDFromIDString(%v) but no error was found", s)
		}
	}

	for _, s := range notHexEntryandUUIDs {
		// TODO: check for correct error
		if _, err := GetUUIDFromIDString(s); err == nil {
			t.Errorf("expected invalid hex error for GetUUIDFromIDString(%v) but no error was found", s)
		}
	}

	// Return entire UUID
	res, err := GetUUIDFromIDString(validUUID)
	if err != nil {
		t.Errorf("unexpected error for GetUUIDFromIDString(%v): %v", validUUID, err)
	}
	if res != validUUID {
		t.Errorf("expected result %v for GetUUIDFromIDString(%v) but got %v", validUUID, validUUID, res)
	}

	// Return UUID from EntryID
	for _, s := range validEntryIDs {
		res, err := GetUUIDFromIDString(s)
		if err != nil {
			t.Errorf("unexpected error for GetUUIDFromIDString(%v): %v", s, err)
		}
		if res != validUUID {
			t.Errorf("expected result %v for GetUUIDFromIDString(%v) but got %v", validUUID, s, res)
		}
	}
}
