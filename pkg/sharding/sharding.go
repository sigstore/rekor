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
	"errors"
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

type EntryID struct {
	TreeID string
	UUID   string
}

// CreateEntryIDFromParts This function can take a TreeID of equal or lesser length than TreeIDHexStringLen. In
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

	if err := ValidateEntryID(treeidFormatted + uuid); err != nil {
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

// GetUUIDFromIDString Returns UUID (with no prepended TreeID) from a UUID or EntryID string.
// Validates UUID and also TreeID if present.
func GetUUIDFromIDString(id string) (string, error) {
	switch len(id) {
	case UUIDHexStringLen:
		if err := ValidateUUID(id); err != nil {
			return "", err
		}
		return id, nil

	case EntryIDHexStringLen:
		if err := ValidateEntryID(id); err != nil {
			if err.Error() == "0 is not a valid TreeID" {
				return id[len(id)-UUIDHexStringLen:], nil
			}
			return "", err
		}
		return id[len(id)-UUIDHexStringLen:], nil

	default:
		return "", fmt.Errorf("invalid ID len %v for %v", len(id), id)
	}
}

// ValidateUUID This is permissive in that if passed an EntryID, it will find the UUID and validate it.
func ValidateUUID(u string) error {
	switch len(u) {
	// If u is an EntryID, call validate on just the UUID
	case EntryIDHexStringLen:
		uid := u[len(u)-UUIDHexStringLen:]
		if err := ValidateUUID(uid); err != nil {
			return err
		}
		return nil
	case UUIDHexStringLen:
		if _, err := hex.DecodeString(u); err != nil {
			return fmt.Errorf("id %v is not a valid hex string: %w", u, err)
		}
		return nil
	default:
		return fmt.Errorf("invalid ID len %v for %v", len(u), u)
	}
}

// ValidateTreeID This is permissive in that if passed an EntryID, it will find the TreeID and validate it.
func ValidateTreeID(t string) error {
	switch len(t) {
	// If t is an EntryID, call validate on just the TreeID
	case EntryIDHexStringLen:
		tid := t[:TreeIDHexStringLen]
		err := ValidateTreeID(tid)
		if err != nil {
			return err
		}
		return nil
	case TreeIDHexStringLen:
		// Check that it's a valid int64 in hex (base 16)
		i, err := strconv.ParseInt(t, 16, 64)
		if err != nil {
			return fmt.Errorf("could not convert treeID %v to int64: %w", t, err)
		}

		// Check for invalid TreeID values
		// TODO: test for more of these
		if i == 0 {
			return errors.New("0 is not a valid TreeID")
		}

		return nil
	default:
		return fmt.Errorf("TreeID len expected to be %v but got %v", TreeIDHexStringLen, len(t))
	}
}

func ValidateEntryID(id string) error {
	UUIDErr := ValidateUUID(id)
	if UUIDErr != nil {
		return UUIDErr
	}

	treeIDErr := ValidateTreeID(id)
	if treeIDErr != nil {
		return treeIDErr
	}

	return nil
}

var ErrPlainUUID = errors.New("cannot get treeID from plain UUID")

// GetTreeIDFromIDString Returns TreeID (with no appended UUID) from a TreeID or EntryID string.
// Validates TreeID and also UUID if present.
func GetTreeIDFromIDString(id string) (string, error) {
	switch len(id) {
	case UUIDHexStringLen:
		return "", ErrPlainUUID
	case EntryIDHexStringLen, TreeIDHexStringLen:
		if err := ValidateEntryID(id); err != nil {
			return "", err
		}
		return id[:TreeIDHexStringLen], nil
	default:
		return "", fmt.Errorf("invalid ID len %v for %v", len(id), id)
	}
}

func TreeID(entryID string) (int64, error) {
	tid, err := GetTreeIDFromIDString(entryID)
	if err != nil {
		return 0, err
	}
	i, err := strconv.ParseInt(tid, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("could not convert treeID %v to int64: %w", tid, err)
	}
	return i, nil
}
