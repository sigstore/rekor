/*
Copyright © 2020 Bob Callaway <bcallawa@redhat.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package api

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/trillian"

	"github.com/go-openapi/swag"

	"google.golang.org/grpc/codes"

	"github.com/projectrekor/rekor/pkg/types"

	"github.com/projectrekor/rekor/pkg/generated/models"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	tclient "github.com/google/trillian/client"
	tcrypto "github.com/google/trillian/crypto"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/projectrekor/rekor/pkg/generated/restapi/operations/entries"
)

func GetLogEntryByIndexHandler(params entries.GetLogEntryByIndexParams) middleware.Responder {
	tc := NewTrillianClient(params.HTTPRequest.Context())

	resp := tc.getLeafByIndex(params.LogIndex)
	switch resp.status {
	case codes.OK:
	case codes.NotFound, codes.OutOfRange:
		return handleRekorAPIError(params, http.StatusNotFound, fmt.Errorf("grpc error: %w", resp.err), "")
	default:
		return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("grpc err: %w", resp.err), trillianCommunicationError)
	}

	leaves := resp.getLeafByRangeResult.GetLeaves()
	if len(leaves) > 1 {
		return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("len(leaves): %v", len(leaves)), trillianUnexpectedResult)
	} else if len(leaves) == 0 {
		return handleRekorAPIError(params, http.StatusNotFound, errors.New("grpc returned 0 leaves with success code"), "")
	}
	leaf := leaves[0]

	logEntry := models.LogEntry{
		hex.EncodeToString(leaf.MerkleLeafHash): models.LogEntryAnon{
			LogIndex: &leaf.LeafIndex,
			Body:     leaf.LeafValue,
		},
	}
	return entries.NewGetLogEntryByIndexOK().WithPayload(logEntry)
}

func CreateLogEntryHandler(params entries.CreateLogEntryParams) middleware.Responder {
	httpReq := params.HTTPRequest
	entry, err := types.NewEntry(params.ProposedEntry)
	if err != nil {
		return handleRekorAPIError(params, http.StatusBadRequest, err, err.Error())
	}

	leaf, err := entry.Canonicalize(httpReq.Context())
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, err, failedToGenerateCanonicalEntry)
	}

	tc := NewTrillianClient(httpReq.Context())

	resp := tc.addLeaf(leaf)
	switch resp.status {
	case codes.OK:
	case codes.AlreadyExists, codes.FailedPrecondition:
		return handleRekorAPIError(params, http.StatusConflict, fmt.Errorf("grpc error: %w", resp.err), entryAlreadyExists)
	default:
		return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("grpc error: %w", resp.err), trillianUnexpectedResult)
	}

	queuedLeaf := resp.getAddResult.QueuedLeaf.Leaf

	uuid := hex.EncodeToString(queuedLeaf.GetMerkleLeafHash())

	logEntry := models.LogEntry{
		uuid: models.LogEntryAnon{
			//LogIndex is not given here because it is always returned as 0
			Body: queuedLeaf.GetLeafValue(),
		},
	}

	location := strfmt.URI(fmt.Sprintf("%v/%v", httpReq.URL, uuid))
	return entries.NewCreateLogEntryCreated().WithPayload(logEntry).WithLocation(location).WithETag(uuid)
}

func GetLogEntryByUUIDHandler(params entries.GetLogEntryByUUIDParams) middleware.Responder {
	hashValue, _ := hex.DecodeString(params.EntryUUID)
	hashes := [][]byte{hashValue}

	tc := NewTrillianClient(params.HTTPRequest.Context())

	resp := tc.getLeafByHash(hashes) // TODO: if this API is deprecated, we need to ask for inclusion proof and then use index in proof result to get leaf
	switch resp.status {
	case codes.OK:
	case codes.NotFound:
		return handleRekorAPIError(params, http.StatusNotFound, fmt.Errorf("grpc error: %w", resp.err), "")
	default:
		return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("grpc error: %w", resp.err), trillianUnexpectedResult)
	}

	leaves := resp.getLeafResult.GetLeaves()
	if len(leaves) > 1 {
		return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("len(leaves): %v", len(leaves)), trillianUnexpectedResult)
	} else if len(leaves) == 0 {
		return handleRekorAPIError(params, http.StatusNotFound, errors.New("grpc returned 0 leaves with success code"), "")
	}
	leaf := leaves[0]

	uuid := hex.EncodeToString(leaf.GetMerkleLeafHash())

	logEntry := models.LogEntry{
		uuid: models.LogEntryAnon{
			LogIndex: swag.Int64(leaf.GetLeafIndex()),
			Body:     leaf.LeafValue,
		},
	}
	return entries.NewGetLogEntryByUUIDOK().WithPayload(logEntry)
}

func GetLogEntryProofHandler(params entries.GetLogEntryProofParams) middleware.Responder {
	hashValue, _ := hex.DecodeString(params.EntryUUID)
	tc := NewTrillianClient(params.HTTPRequest.Context())

	resp := tc.getProofByHash(hashValue)
	switch resp.status {
	case codes.OK:
	case codes.NotFound:
		return handleRekorAPIError(params, http.StatusNotFound, fmt.Errorf("grpc error: %w", resp.err), "")
	default:
		return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("grpc error: %w", resp.err), trillianUnexpectedResult)
	}
	result := resp.getProofResult

	// validate result is signed with the key we're aware of
	pub, err := x509.ParsePKIXPublicKey(tc.pubkey.Der)
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, err, "")
	}
	verifier := tclient.NewLogVerifier(rfc6962.DefaultHasher, pub, crypto.SHA256)
	root, err := tcrypto.VerifySignedLogRoot(verifier.PubKey, verifier.SigHash, result.SignedLogRoot)
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, err, trillianUnexpectedResult)
	}

	if len(result.Proof) != 1 {
		return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("len(result.Proof) = %v", len(result.Proof)), trillianUnexpectedResult)
	}
	proof := result.Proof[0]

	hashes := []string{}
	for _, hash := range proof.Hashes {
		hashes = append(hashes, hex.EncodeToString(hash))
	}

	inclusionProof := models.InclusionProof{
		TreeSize: swag.Int64(int64(root.TreeSize)),
		RootHash: swag.String(hex.EncodeToString(root.RootHash)),
		LogIndex: swag.Int64(proof.GetLeafIndex()),
		Hashes:   hashes,
	}
	return entries.NewGetLogEntryProofOK().WithPayload(&inclusionProof)
}

func SearchLogQueryHandler(params entries.SearchLogQueryParams) middleware.Responder {
	httpReqCtx := params.HTTPRequest.Context()
	resultPayload := []models.LogEntry{}
	tc := NewTrillianClient(httpReqCtx)

	//TODO: parallelize this into different goroutines to speed up search
	searchHashes := [][]byte{}
	if len(params.Entry.EntryUUIDs) > 0 || len(params.Entry.Entries()) > 0 {
		for _, uuid := range params.Entry.EntryUUIDs {
			hash, err := hex.DecodeString(uuid)
			if err != nil {
				return handleRekorAPIError(params, http.StatusBadRequest, err, malformedUUID)
			}
			searchHashes = append(searchHashes, hash)
		}

		for _, e := range params.Entry.Entries() {
			entry, err := types.NewEntry(e)
			if err != nil {
				return handleRekorAPIError(params, http.StatusBadRequest, err, err.Error())
			}

			if entry.HasExternalEntities() {
				if err := entry.FetchExternalEntities(httpReqCtx); err != nil {
					return handleRekorAPIError(params, http.StatusBadRequest, err, err.Error())
				}
			}

			leaf, err := entry.Canonicalize(httpReqCtx)
			if err != nil {
				return handleRekorAPIError(params, http.StatusInternalServerError, err, err.Error())
			}
			hasher := rfc6962.DefaultHasher
			leafHash := hasher.HashLeaf(leaf)
			searchHashes = append(searchHashes, leafHash)
		}

		resp := tc.getLeafByHash(searchHashes) // TODO: if this API is deprecated, we need to ask for inclusion proof and then use index in proof result to get leaf
		switch resp.status {
		case codes.OK, codes.NotFound:
		default:
			return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("grpc error: %w", resp.err), trillianUnexpectedResult)
		}

		for _, leaf := range resp.getLeafResult.Leaves {
			logEntry := models.LogEntry{
				hex.EncodeToString(leaf.MerkleLeafHash): models.LogEntryAnon{
					LogIndex: &leaf.LeafIndex,
					Body:     leaf.LeafValue,
				},
			}
			resultPayload = append(resultPayload, logEntry)
		}
	}

	if len(params.Entry.LogIndexes) > 0 {
		leaves := []*trillian.LogLeaf{}
		for _, logIndex := range params.Entry.LogIndexes {
			resp := tc.getLeafByIndex(swag.Int64Value(logIndex))
			switch resp.status {
			case codes.OK, codes.NotFound:
			default:
				return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("grpc error: %w", resp.err), trillianUnexpectedResult)
			}
			leaves = append(leaves, resp.getLeafResult.Leaves...)
		}

		for _, leaf := range leaves {
			logEntry := models.LogEntry{
				hex.EncodeToString(leaf.MerkleLeafHash): models.LogEntryAnon{
					LogIndex: &leaf.LeafIndex,
					Body:     leaf.LeafValue,
				},
			}
			resultPayload = append(resultPayload, logEntry)
		}
	}

	return entries.NewSearchLogQueryOK().WithPayload(resultPayload)
}
