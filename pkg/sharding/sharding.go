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
	"encoding/hex"
	"fmt"
	"strconv"
)

// An EntryID refers to a specific artifact's ID and is made of two components,
// the TreeID and the UUID. The TreeID is a hex-encoded uint64 (8 bytes)
// referring to the specific trillian tree (also known as log or shard) where
// the artifact can be found. The UUID is a hex-encoded 32-byte number
// referring to the artifact's merkle leaf hash from trillian. Artifact lookup
// by UUID occurs by finding the UUID within the tree specified by the TreeID.
//
// An EntryID is 40 bytes long and looks like this:
// FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF
// |_______  ________| |_____________________________________  ______________________________________|
//         \/                                                \/
// TreeID (8 bytes, hex)                             UUID (32 bytes, hex)

const TreeIDHexStringLen = 16
const UUIDHexStringLen = 64
const EntryIDHexStringLen = TreeIDHexStringLen + UUIDHexStringLen

// TODO: replace this with the actual LogRanges struct when logic is hooked up
var dummyLogRanges = LogRanges{
	Ranges: []LogRange{
		{
			TreeID:     0,
			TreeLength: 0}},
}

type EntryID struct {
	TreeID string
	UUID   string
}

// This function can take a TreeID of equal or greater length than TreeIDHexStringLen. In
// case the TreeID length is less than TreeIDHexStringLen, it will be padded to the correct
// length.
func CreateEntryIDFromParts(treeid string, uuid string) (EntryID, error) {
	if len(treeid) > TreeIDHexStringLen {
		err := fmt.Errorf("invalid treeid len: %v", len(treeid))
		return createEmptyEntryID(), err
	}

	if len(uuid) != UUIDHexStringLen {
		err := fmt.Errorf("invalid uuid len: %v", len(uuid))
		return createEmptyEntryID(), err
	}

	treeidFormatted, err := PadToTreeIDLen(treeid)
	if err != nil {
		return createEmptyEntryID(), err
	}

	if _, err := hex.DecodeString(treeidFormatted); err != nil {
		err := fmt.Errorf("treeid %v is not a valid hex string: %v", treeidFormatted, err)
		return createEmptyEntryID(), err
	}

	if _, err := hex.DecodeString(uuid); err != nil {
		err := fmt.Errorf("uuid %v is not a valid hex string: %v", uuid, err)
		return createEmptyEntryID(), err
	}

	return EntryID{
		TreeID: treeidFormatted,
		UUID:   uuid}, nil
}

func createEmptyEntryID() EntryID {
	return EntryID{
		TreeID: "",
		UUID:   ""}
}

func CreateEntryIDWithActiveTreeID(uuid string) (EntryID, error) {
	// TODO: Update this to be the global LogRanges struct
	treeid := strconv.FormatUint(dummyLogRanges.ActiveIndex(), 10)
	return CreateEntryIDFromParts(treeid, uuid)
}

func (e EntryID) ReturnEntryIDString() string {
	return e.TreeID + e.UUID
}

func PadToTreeIDLen(t string) (string, error) {
	switch {
	case len(t) == TreeIDHexStringLen:
		return t, nil
	case len(t) > TreeIDHexStringLen:
		return "", fmt.Errorf("invalid treeID %v: too long", t)
	default:
		return fmt.Sprintf("%016s", t), nil
	}
}

// Returns UUID (with no prepended TreeID) from a UUID or EntryID string
func GetUUIDFromIDString(id string) (string, error) {
	if len(id) != UUIDHexStringLen && len(id) != EntryIDHexStringLen {
		return "", fmt.Errorf("invalid ID len %v for %v", len(id), id)
	}

	if _, err := hex.DecodeString(id); err != nil {
		return "", fmt.Errorf("id %v is not a valid hex string: %v", id, err)
	}

	return id[len(id)-UUIDHexStringLen:], nil
}
