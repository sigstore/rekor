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

package app

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"strconv"

	"github.com/google/trillian/merkle/logverifier"
	rfc6962 "github.com/google/trillian/merkle/rfc6962/hasher"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/sigstore/rekor/cmd/rekor-cli/app/format"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/log"
)

type verifyCmdOutput struct {
	RootHash  string
	EntryUUID string
	Index     int64
	Size      int64
	Hashes    []string
}

func (v *verifyCmdOutput) String() string {
	s := fmt.Sprintf("Current Root Hash: %v\n", v.RootHash)
	s += fmt.Sprintf("Entry Hash: %v\n", v.EntryUUID)
	s += fmt.Sprintf("Entry Index: %v\n", v.Index)
	s += fmt.Sprintf("Current Tree Size: %v\n\n", v.Size)

	s += "Inclusion Proof:\n"
	hasher := rfc6962.DefaultHasher
	inner := bits.Len64(uint64(v.Index ^ (v.Size - 1)))
	var left, right []byte
	result, _ := hex.DecodeString(v.EntryUUID)
	for i, h := range v.Hashes {
		if i < inner && (v.Index>>uint(i))&1 == 0 {
			left = result
			right, _ = hex.DecodeString(h)
		} else {
			left, _ = hex.DecodeString(h)
			right = result
		}
		result = hasher.HashChildren(left, right)
		s += fmt.Sprintf("SHA256(0x01 | %v | %v) =\n\t%v\n\n",
			hex.EncodeToString(left), hex.EncodeToString(right), hex.EncodeToString(result))
	}
	return s
}

// verifyCmd represents the get command
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Rekor verify command",
	Long:  `Verifies an entry exists in the transparency log through an inclusion proof`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// these are bound here so that they are not overwritten by other commands
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			return fmt.Errorf("error initializing cmd line args: %s", err)
		}
		if err := validateArtifactPFlags(true, true); err != nil {
			_ = cmd.Help()
			return err
		}
		return nil
	},
	Run: format.WrapCmd(func(args []string) (interface{}, error) {
		rekorClient, err := GetRekorClient(viper.GetString("rekor_server"))
		if err != nil {
			return nil, err
		}

		searchParams := entries.NewSearchLogQueryParams()
		searchLogQuery := models.SearchLogQuery{}

		uuid := viper.GetString("uuid")
		logIndex := viper.GetString("log-index")

		if uuid != "" {
			searchLogQuery.EntryUUIDs = append(searchLogQuery.EntryUUIDs, uuid)
		} else if logIndex != "" {
			logIndexInt, err := strconv.ParseInt(logIndex, 10, 0)
			if err != nil {
				return nil, fmt.Errorf("error parsing --log-index: %w", err)
			}
			searchLogQuery.LogIndexes = []*int64{&logIndexInt}
		} else {
			var entry models.ProposedEntry
			switch viper.GetString("type") {
			case "rekord":
				entry, err = CreateRekordFromPFlags()
				if err != nil {
					return nil, err
				}
			case "rpm":
				entry, err = CreateRpmFromPFlags()
				if err != nil {
					return nil, err
				}
			default:
				return nil, errors.New("invalid type specified")
			}

			entries := []models.ProposedEntry{entry}
			searchLogQuery.SetEntries(entries)
		}
		searchParams.SetEntry(&searchLogQuery)

		resp, err := rekorClient.Entries.SearchLogQuery(searchParams)
		if err != nil {
			return nil, err
		}

		if len(resp.Payload) == 0 {
			return nil, fmt.Errorf("entry in log cannot be located")
		} else if len(resp.Payload) > 1 {
			return nil, fmt.Errorf("multiple entries returned; this should not happen")
		}
		logEntry := resp.Payload[0]

		var o *verifyCmdOutput
		for k, v := range logEntry {
			o = &verifyCmdOutput{
				RootHash:  *v.Verification.InclusionProof.RootHash,
				EntryUUID: k,
				Index:     *v.LogIndex,
				Size:      *v.Verification.InclusionProof.TreeSize,
				Hashes:    v.Verification.InclusionProof.Hashes,
			}
		}

		hashes := [][]byte{}
		for _, h := range o.Hashes {
			hb, _ := hex.DecodeString(h)
			hashes = append(hashes, hb)
		}

		rootHash, _ := hex.DecodeString(o.RootHash)
		leafHash, _ := hex.DecodeString(o.EntryUUID)

		v := logverifier.New(rfc6962.DefaultHasher)
		if err := v.VerifyInclusionProof(o.Index, o.Size, hashes, rootHash, leafHash); err != nil {
			return nil, err
		}
		return o, err
	}),
}

func init() {
	if err := addArtifactPFlags(verifyCmd); err != nil {
		log.Logger.Fatal("Error parsing cmd line args:", err)
	}
	if err := addUUIDPFlags(verifyCmd, false); err != nil {
		log.Logger.Fatal("Error parsing cmd line args:", err)
	}
	if err := addLogIndexFlag(verifyCmd, false); err != nil {
		log.Logger.Fatal("Error parsing cmd line args:", err)
	}

	rootCmd.AddCommand(verifyCmd)
}
