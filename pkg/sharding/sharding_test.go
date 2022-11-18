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

import "testing"

// Create some test data
// Good data
const validTreeID1 = "0FFFFFFFFFFFFFFF"

const (
	validTreeID2 = "3315648d077a9f02"
	validTreeID3 = "7241b7903737211c"
	shortTreeID  = "12345"
)

const validUUID = "f794467401d57241b7903737211c721cb3315648d077a9f02ceefb6e404a05de"

const (
	validEntryID1 = validTreeID1 + validUUID
	validEntryID2 = validTreeID2 + validUUID
	validEntryID3 = validTreeID3 + validUUID
)

var (
	validTreeIDs  = []string{validTreeID1, validTreeID2, validTreeID3, shortTreeID}
	validEntryIDs = []string{validEntryID1, validEntryID2, validEntryID3}
)

// Bad data
// Unknown TreeID
const invalidTreeID = "0000000000000000"
const invalidEntryID = invalidTreeID + validUUID

// Wrong length
const tooLongTreeID = validTreeID1 + "e"

const tooLongUUID = validUUID + "e"

var tooShortUUID = validUUID[:len(validUUID)-1]

const tooLongEntryID = validEntryID1 + "e"

var tooShortEntryID = validEntryID1[:len(validEntryID1)-1]

var (
	wrongLengthTreeIDs       = []string{tooLongTreeID, validEntryID3, validUUID}
	wrongLengthUUIDs         = []string{tooShortUUID, tooLongUUID, validEntryID3, validTreeID1}
	wrongLengthEntryandUUIDs = []string{tooLongEntryID, tooShortEntryID, tooLongUUID, tooShortUUID, validTreeID3}
)

// Not valid hex
const notHexTreeID1 = "ZZZZZZZZZZZZZZZZ"

const (
	notHexTreeID2 = "FFFFFFF_FFFFFFFF"
	notHexTreeID3 = "xxFFFFFFFFFFFFFF"
)

const (
	notHexUUID1 = "94467401d57241b7903737211c721cb3315648d077a9f02ceefb6e404a05dezq"
	notHexUUID2 = "y794467401d57241b7903737211c721cb3315648d077a9f02ceefb6e404a05de"
	notHexUUID3 = "f794467401d57241b7903737211c721cbp3315648d077a9f02ceefb6e404a05d"
)

const (
	notHexEntryID1 = notHexTreeID1 + validUUID
	notHexEntryID2 = validTreeID2 + notHexUUID1
	notHexEntryID3 = notHexTreeID2 + notHexUUID3
)

var (
	notHexTreeIDs       = []string{notHexTreeID1, notHexTreeID2, notHexTreeID3}
	notHexUUIDs         = []string{notHexUUID1, notHexUUID2, notHexUUID3}
	notHexEntryandUUIDs = []string{notHexEntryID1, notHexEntryID2, notHexEntryID3, notHexUUID1, notHexUUID2, notHexUUID3}
)

// Test functions
func TestCreateEntryIDFromParts(t *testing.T) {
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

func TestGetTreeIDFromIDString(t *testing.T) {
	valid1, err := GetTreeIDFromIDString(validEntryID1)
	if valid1 != validTreeID1 || err != nil {
		t.Errorf("expected TreeID %v with nil error, got: %v with error %v", validTreeID1, valid1, err)
	}
	valid2, err := GetTreeIDFromIDString(validEntryID2)
	if valid2 != validTreeID2 || err != nil {
		t.Errorf("expected TreeID %v with nil error, got: %v with error %v", validTreeID2, valid2, err)
	}
	valid3, err := GetTreeIDFromIDString(validEntryID3)
	if valid3 != validTreeID3 || err != nil {
		t.Errorf("expected TreeID %v with nil error, got: %v with error %v", validTreeID3, valid3, err)
	}

	// tree IDs of zero should return an error
	invalid, err := GetTreeIDFromIDString(invalidEntryID)
	if invalid != "" || err.Error() != "0 is not a valid TreeID" {
		t.Errorf("expected err 'unknown treeID', got: %v with error %v", invalid, err)
	}

	// invalid UUID should also return an error because we test inclusively for
	// malformed parts of EntryID
	_, e := GetTreeIDFromIDString(notHexEntryID2)
	if e == nil {
		t.Errorf("expected error for invalid UUID, but got none")
	}
	// uuid length error
	uuidHexStringLen := "qlALqZuNP9Iqpg2WVAOkJUntCXQtOOQpOfqox5JbJK4jw5xBs53Wqu1WQ5vTfvqr"
	_, e = GetTreeIDFromIDString(uuidHexStringLen)
	if e == nil {
		t.Errorf("expected error for invalid TreeID, but got none")
	}
	invalidStringLength := "FWQfOtwd7I4BcCZ5OU7Hbmmp"
	_, e = GetTreeIDFromIDString(invalidStringLength)
	if e == nil {
		t.Errorf("expected error for invalid TreeID, but got none")
	}
}

func TestTreeID(t *testing.T) {
	type args struct {
		entryID string
	}
	tests := []struct {
		name    string
		args    args
		want    int64
		wantErr bool
	}{
		{
			name: "valid entryID",
			args: args{
				entryID: validEntryID1,
			},
			want:    1152921504606846975,
			wantErr: false,
		},
		{
			name: "invalid entryID",
			args: args{
				entryID: invalidEntryID,
			},
			want:    0,
			wantErr: true,
		},
		{
			name: "invalid UUID",
			args: args{
				entryID: notHexEntryID2,
			},
			want:    0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TreeID(tt.args.entryID)
			if (err != nil) != tt.wantErr {
				t.Errorf("TreeID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("TreeID() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateTreeID(t *testing.T) {
	type args struct {
		t string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid treeID",
			args: args{
				t: validTreeID1,
			},
			wantErr: false,
		},
		{
			name: "invalid treeID",
			args: args{
				t: invalidTreeID,
			},
			wantErr: true,
		},
		{
			name: "invalid UUID",
			args: args{
				t: notHexTreeID2,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateTreeID(tt.args.t); (err != nil) != tt.wantErr {
				t.Errorf("ValidateTreeID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
