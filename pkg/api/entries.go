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
	"fmt"
	"net/http"

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
	api, _ := NewAPI(params.HTTPRequest.Context())

	indexes := []int64{params.LogIndex}
	resp, err := api.client.getLeafByIndex(indexes)
	if err != nil {
		code := http.StatusInternalServerError
		return logAndReturnError(entries.NewGetLogEntryByIndexDefault(code), code, err, trillianCommunicationError, params.HTTPRequest)
	}
	switch resp.status {
	case codes.OK:
	case codes.NotFound, codes.OutOfRange:
		return logAndReturnError(entries.NewGetLogEntryByIndexNotFound(), http.StatusNotFound, nil, "", params.HTTPRequest)
	default:
		code := http.StatusInternalServerError
		return logAndReturnError(entries.NewGetLogEntryByIndexDefault(code), code, nil, trillianCommunicationError, params.HTTPRequest)
	}

	leaves := resp.getLeafByIndexResult.GetLeaves()
	if len(leaves) > 1 {
		code := http.StatusInternalServerError
		return logAndReturnError(entries.NewGetLogEntryByIndexDefault(code), code, nil, trillianUnexpectedResult, params.HTTPRequest)
	} else if len(leaves) == 0 {
		return logAndReturnError(entries.NewGetLogEntryByIndexNotFound(), http.StatusNotFound, nil, "", params.HTTPRequest)
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
	entry, err := types.NewEntry(params.ProposedEntry)
	if err != nil {
		return logAndReturnError(entries.NewCreateLogEntryBadRequest(), http.StatusBadRequest, err, err.Error(), params.HTTPRequest)
	}

	leaf, err := entry.Canonicalize(params.HTTPRequest.Context())
	if err != nil {
		code := http.StatusInternalServerError
		return logAndReturnError(entries.NewCreateLogEntryDefault(code), code, err, failedToGenerateCanonicalEntry, params.HTTPRequest)
	}

	api, _ := NewAPI(params.HTTPRequest.Context())
	resp, err := api.client.addLeaf(leaf)
	if err != nil {
		code := http.StatusInternalServerError
		return logAndReturnError(entries.NewCreateLogEntryDefault(code), code, err, trillianCommunicationError, params.HTTPRequest)
	}
	switch resp.status {
	case codes.OK:
	case codes.AlreadyExists, codes.FailedPrecondition:
		return logAndReturnError(entries.NewCreateLogEntryConflict(), http.StatusConflict, nil, entryAlreadyExists, params.HTTPRequest)
	default:
		code := http.StatusInternalServerError
		return logAndReturnError(entries.NewCreateLogEntryDefault(code), code, nil, trillianUnexpectedResult, params.HTTPRequest)
	}

	queuedLeaf := resp.getAddResult.QueuedLeaf.Leaf

	uuid := hex.EncodeToString(queuedLeaf.GetMerkleLeafHash())

	logEntry := models.LogEntry{
		uuid: models.LogEntryAnon{
			//LogIndex is not given here because it is always returned as 0
			Body: queuedLeaf.GetLeafValue(),
		},
	}

	location := strfmt.URI(fmt.Sprintf("%v/%v", params.HTTPRequest.URL, uuid))
	return entries.NewCreateLogEntryCreated().WithPayload(logEntry).WithLocation(location).WithETag(uuid)
}

func GetLogEntryByUUIDHandler(params entries.GetLogEntryByUUIDParams) middleware.Responder {
	api, _ := NewAPI(params.HTTPRequest.Context())
	hashValue, _ := hex.DecodeString(params.EntryUUID)
	hashes := [][]byte{hashValue}
	resp, err := api.client.getLeafByHash(hashes)
	if err != nil {
		code := http.StatusInternalServerError
		return logAndReturnError(entries.NewGetLogEntryByUUIDDefault(code), code, err, trillianCommunicationError, params.HTTPRequest)
	}
	switch resp.status {
	case codes.OK:
	case codes.NotFound:
		return logAndReturnError(entries.NewGetLogEntryByUUIDNotFound(), http.StatusNotFound, nil, "", params.HTTPRequest)
	default:
		code := http.StatusInternalServerError
		return logAndReturnError(entries.NewGetLogEntryByUUIDDefault(code), code, nil, trillianUnexpectedResult, params.HTTPRequest)
	}

	leaves := resp.getLeafResult.GetLeaves()
	if len(leaves) > 1 {
		code := http.StatusInternalServerError
		return logAndReturnError(entries.NewGetLogEntryByUUIDDefault(code), code, nil, trillianUnexpectedResult, params.HTTPRequest)
	} else if len(leaves) == 0 {
		return logAndReturnError(entries.NewGetLogEntryByUUIDNotFound(), http.StatusNotFound, nil, "", params.HTTPRequest)
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
	api, _ := NewAPI(params.HTTPRequest.Context())
	hashValue, _ := hex.DecodeString(params.EntryUUID)
	resp, err := api.client.getProofByHash(hashValue)
	if err != nil {
		code := http.StatusInternalServerError
		return logAndReturnError(entries.NewGetLogEntryProofDefault(code), code, err, trillianCommunicationError, params.HTTPRequest)
	}
	switch resp.status {
	case codes.OK:
	case codes.NotFound:
		return logAndReturnError(entries.NewGetLogEntryProofNotFound(), http.StatusNotFound, nil, "", params.HTTPRequest)
	default:
		code := http.StatusInternalServerError
		return logAndReturnError(entries.NewGetLogEntryProofDefault(code), code, nil, trillianUnexpectedResult, params.HTTPRequest)
	}
	result := resp.getProofResult

	// validate result is signed with the key we're aware of
	pub, err := x509.ParsePKIXPublicKey(api.pubkey.Der)
	if err != nil {
		code := http.StatusInternalServerError
		return logAndReturnError(entries.NewGetLogEntryProofDefault(code), code, err, http.StatusText(code), params.HTTPRequest)
	}
	verifier := tclient.NewLogVerifier(rfc6962.DefaultHasher, pub, crypto.SHA256)
	root, err := tcrypto.VerifySignedLogRoot(verifier.PubKey, verifier.SigHash, result.SignedLogRoot)
	if err != nil {
		code := http.StatusInternalServerError
		return logAndReturnError(entries.NewGetLogEntryProofDefault(code), code, err, trillianUnexpectedResult, params.HTTPRequest)
	}

	if len(result.Proof) != 1 {
		code := http.StatusInternalServerError
		return logAndReturnError(entries.NewGetLogEntryProofDefault(code), code, nil, trillianUnexpectedResult, params.HTTPRequest)
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
	resultPayload := []models.LogEntry{}
	api, _ := NewAPI(params.HTTPRequest.Context())

	//TODO: parallelize this into different goroutines to speed up search
	searchHashes := [][]byte{}
	if len(params.Entry.EntryUUIDs) > 0 || len(params.Entry.Entries()) > 0 {
		for _, uuid := range params.Entry.EntryUUIDs {
			hash, err := hex.DecodeString(uuid)
			if err != nil {
				code := http.StatusBadRequest
				return logAndReturnError(entries.NewSearchLogQueryBadRequest(), code, err, http.StatusText(code), params.HTTPRequest)
			}
			searchHashes = append(searchHashes, hash)
		}

		for _, e := range params.Entry.Entries() {
			entry, err := types.NewEntry(e)
			if err != nil {
				code := http.StatusBadRequest
				return logAndReturnError(entries.NewSearchLogQueryBadRequest(), code, err, err.Error(), params.HTTPRequest)
			}

			if entry.HasExternalEntities() {
				if err := entry.FetchExternalEntities(params.HTTPRequest.Context()); err != nil {
					code := http.StatusBadRequest
					return logAndReturnError(entries.NewSearchLogQueryDefault(code), code, err, err.Error(), params.HTTPRequest)
				}
			}

			leaf, err := entry.Canonicalize(params.HTTPRequest.Context())
			if err != nil {
				code := http.StatusInternalServerError
				return logAndReturnError(entries.NewSearchLogQueryDefault(code), code, err, err.Error(), params.HTTPRequest)
			}
			hasher := rfc6962.DefaultHasher
			leafHash := hasher.HashLeaf(leaf)
			searchHashes = append(searchHashes, leafHash)
		}

		resp, err := api.client.getLeafByHash(searchHashes)
		if err != nil {
			code := http.StatusInternalServerError
			return logAndReturnError(entries.NewSearchLogQueryDefault(code), code, err, trillianCommunicationError, params.HTTPRequest)
		}
		switch resp.status {
		case codes.OK, codes.NotFound:
		default:
			code := http.StatusInternalServerError
			return logAndReturnError(entries.NewSearchLogQueryDefault(code), code, nil, trillianUnexpectedResult, params.HTTPRequest)
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
		resp, err := api.client.getLeafByIndex(swag.Int64ValueSlice(params.Entry.LogIndexes))
		if err != nil {
			code := http.StatusInternalServerError
			return logAndReturnError(entries.NewSearchLogQueryDefault(code), code, err, trillianCommunicationError, params.HTTPRequest)
		}
		switch resp.status {
		case codes.OK, codes.NotFound:
		default:
			code := http.StatusInternalServerError
			return logAndReturnError(entries.NewSearchLogQueryDefault(code), code, nil, trillianUnexpectedResult, params.HTTPRequest)
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

	return entries.NewSearchLogQueryOK().WithPayload(resultPayload)
}
