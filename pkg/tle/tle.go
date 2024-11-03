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

package tle

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	rekor_pb_common "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	rekor_pb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/transparency-dev/merkle/rfc6962"
	"google.golang.org/protobuf/encoding/protojson"
)

const TLEMediaType = "application/x-sigstore-tle"

// GenerateTransparencyLogEntry returns a sigstore/protobuf-specs compliant message containing a
// TransparencyLogEntry as defined at https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_rekor.proto
func GenerateTransparencyLogEntry(anon models.LogEntryAnon) (*rekor_pb.TransparencyLogEntry, error) {
	logIDHash, err := hex.DecodeString(*anon.LogID)
	if err != nil {
		return nil, fmt.Errorf("decoding logID string: %w", err)
	}

	rootHash, err := hex.DecodeString(*anon.Verification.InclusionProof.RootHash)
	if err != nil {
		return nil, fmt.Errorf("decoding inclusion proof root hash: %w", err)
	}

	inclusionProofHashes := make([][]byte, len(anon.Verification.InclusionProof.Hashes))
	for i, hash := range anon.Verification.InclusionProof.Hashes {
		hashBytes, err := hex.DecodeString(hash)
		if err != nil {
			return nil, fmt.Errorf("decoding inclusion proof hash: %w", err)
		}
		inclusionProofHashes[i] = hashBytes
	}

	// Different call paths may supply string or []byte. If string, it is base64 encoded.
	var body []byte
	switch v := anon.Body.(type) {
	case string:
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("base64 decoding body: %w", err)
		}
		body = b
	case []byte:
		body = v
	default:
		return nil, fmt.Errorf("body is not string or []byte: (%T)%v", v, v)
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(body), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}
	eimpl, err := types.UnmarshalEntry(pe)
	if err != nil {
		return nil, err
	}

	return &rekor_pb.TransparencyLogEntry{
		LogIndex: *anon.LogIndex, // the global log index
		LogId: &rekor_pb_common.LogId{
			KeyId: logIDHash,
		},
		KindVersion: &rekor_pb.KindVersion{
			Kind:    pe.Kind(),
			Version: eimpl.APIVersion(),
		},
		IntegratedTime: *anon.IntegratedTime,
		InclusionPromise: &rekor_pb.InclusionPromise{
			SignedEntryTimestamp: anon.Verification.SignedEntryTimestamp,
		},
		InclusionProof: &rekor_pb.InclusionProof{
			LogIndex: *anon.Verification.InclusionProof.LogIndex, // relative to the specific tree the entry is found in
			RootHash: rootHash,
			TreeSize: *anon.Verification.InclusionProof.TreeSize,
			Hashes:   inclusionProofHashes,
			Checkpoint: &rekor_pb.Checkpoint{
				Envelope: *anon.Verification.InclusionProof.Checkpoint,
			},
		},
		CanonicalizedBody: body, // we don't call eimpl.Canonicalize in the case that the logic is different in this caller vs when it was persisted in the log
	}, nil
}

// MarshalTLEToJSON marshals a TransparencyLogEntry message to JSON according to the protobuf JSON encoding rules
func MarshalTLEToJSON(tle *rekor_pb.TransparencyLogEntry) ([]byte, error) {
	return protojson.Marshal(tle)
}

func GenerateLogEntry(tle *rekor_pb.TransparencyLogEntry) models.LogEntry {
	if tle == nil {
		return nil
	}

	//TODO: do we have the information to prefix the tree ID onto this?
	entryUUID := hex.EncodeToString(rfc6962.DefaultHasher.HashLeaf(tle.CanonicalizedBody))
	inclusionProofHashes := []string{}
	for _, hash := range tle.InclusionProof.Hashes {
		inclusionProofHashes = append(inclusionProofHashes, hex.EncodeToString(hash))
	}
	return models.LogEntry{
		entryUUID: models.LogEntryAnon{
			Body:           base64.StdEncoding.EncodeToString(tle.CanonicalizedBody),
			IntegratedTime: swag.Int64(tle.IntegratedTime),
			LogID:          swag.String(hex.EncodeToString(tle.LogId.KeyId)),
			LogIndex:       swag.Int64(tle.LogIndex),
			Verification: &models.LogEntryAnonVerification{
				InclusionProof: &models.InclusionProof{
					Checkpoint: swag.String(tle.InclusionProof.Checkpoint.GetEnvelope()),
					Hashes:     inclusionProofHashes,
					LogIndex:   swag.Int64(tle.LogIndex),
					RootHash:   swag.String(hex.EncodeToString(tle.InclusionProof.RootHash)),
					TreeSize:   swag.Int64(tle.InclusionProof.TreeSize),
				},
				SignedEntryTimestamp: strfmt.Base64(tle.InclusionPromise.SignedEntryTimestamp),
			},
		},
	}
}

type Producer struct{}

func (t Producer) Produce(w io.Writer, input interface{}) error {
	switch i := input.(type) {
	case models.LogEntry:
		var entry models.LogEntryAnon
		for _, e := range i {
			entry = e
		}
		tle, err := GenerateTransparencyLogEntry(entry)
		if err != nil {
			return err
		}
		tleBytes, err := MarshalTLEToJSON(tle)
		if err != nil {
			return err
		}
		if _, err = io.Copy(w, bytes.NewReader(tleBytes)); err != nil {
			return err
		}
	case []models.LogEntry:
		buf := &bytes.Buffer{}
		if _, err := buf.Write([]byte("[")); err != nil {
			return err
		}
		for num, entry := range i {
			if num != 0 {
				if _, err := buf.Write([]byte(",")); err != nil {
					return err
				}
			}
			if err := t.Produce(buf, entry); err != nil {
				return err
			}
		}
		if _, err := buf.Write([]byte("]")); err != nil {
			return err
		}
		if _, err := io.Copy(w, buf); err != nil {
			return err
		}
	default:
		return errors.New("unexpected type of input")
	}
	return nil
}

type Consumer struct{}

func (t Consumer) Consume(r io.Reader, output interface{}) error {
	tleBytes, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(tleBytes))
	token, err := decoder.Token()
	if err != nil {
		return err
	}

	switch token {
	case json.Delim('['):
		// this is a JSON array, let's check output type to ensure its []rekor_pb.TransparencyLogEntry
		var jsonArray []json.RawMessage
		if err := json.Unmarshal(tleBytes, &jsonArray); err != nil {
			return fmt.Errorf("expected array: %w", err)
		}
		for _, element := range jsonArray {
			msg := &rekor_pb.TransparencyLogEntry{}
			if err := protojson.Unmarshal(element, msg); err != nil {
				return fmt.Errorf("parsing element: %w", err)
			}
			if result, ok := output.(*[]models.LogEntry); ok {
				logEntry := GenerateLogEntry(msg)
				*result = append(*result, logEntry)
			} else if result, ok := output.(*[]*rekor_pb.TransparencyLogEntry); ok {
				*result = append(*result, msg)
			} else {
				return errors.New("unsupported conversion")
			}
		}
		return nil
	case json.Delim('{'):
		// this is a JSON object, let's check output type to ensure its rekor_pb.TransparencyLogEntry
		tle := &rekor_pb.TransparencyLogEntry{}
		if err := protojson.Unmarshal(tleBytes, tle); err != nil {
			return fmt.Errorf("parsing element: %w", err)
		}
		if result, ok := output.(**rekor_pb.TransparencyLogEntry); ok {
			*result = tle
			return nil
		} else if result, ok := output.(*models.LogEntry); ok {
			*result = GenerateLogEntry(tle)
			return nil
		} else {
			return errors.New("unsupported conversion")
		}
	}
	return errors.New("unexpected value")
}
