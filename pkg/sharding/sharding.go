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

// A FullID refers to a specific artifact's ID and is made of two components,
// the TreeID and the UUID. The TreeID is a hex-encoded uint64 (8 bytes)
// referring to the specific trillian tree (also known as log or shard) where
// the artifact can be found. The UUID is a hex-encoded 32-byte number
// referring to the artifact's merkle leaf hash from trillian. Artifact lookup
// by UUID occurs by finding the UUID within the tree specified by the TreeID.
//
// A FullID is 40 bytes long and looks like this:
// FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF
// |_______  ________| |_____________________________________  ______________________________________|
//         \/                                                \/
// TreeID (8 bytes, hex)                             UUID (32 bytes, hex)

const TreeIDHexStringLen = 16
const UUIDHexStringLen = 64
const FullIDHexStringLen = TreeIDHexStringLen + UUIDHexStringLen

// TODO: replace this with the actual LogRanges struct when logic is hooked up
var dummy = LogRanges{
	Ranges: []LogRange{},
}

type FullID struct {
	TreeID string
	UUID   string
}

func CreateFullID(treeid string, uuid string) (FullID, error) {
	if len(treeid) != TreeIDHexStringLen {
		err := fmt.Errorf("invalid treeid len: %v", len(treeid))
		return createEmptyFullID(), err
	}

	if len(uuid) != UUIDHexStringLen {
		err := fmt.Errorf("invalid uuid len: %v", len(uuid))
		return createEmptyFullID(), err
	}

	if _, err := hex.DecodeString(treeid); err != nil {
		err := fmt.Errorf("treeid is not a valid hex string: %v", treeid)
		return createEmptyFullID(), err
	}

	if _, err := hex.DecodeString(uuid); err != nil {
		err := fmt.Errorf("uuid is not a valid hex string: %v", uuid)
		return createEmptyFullID(), err
	}

	return FullID{
		TreeID: treeid,
		UUID:   uuid}, nil
}

func createEmptyFullID() FullID {
	return FullID{
		TreeID: "",
		UUID:   ""}
}

func PrependActiveTreeID(uuid string) (FullID, error) {
	// TODO: Update this to be the global LogRanges struct
	active := dummy.ActiveIndex()
	return CreateFullID(strconv.FormatUint(active, 10), uuid)
}
