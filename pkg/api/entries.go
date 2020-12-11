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
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/go-openapi/swag"

	"google.golang.org/grpc/codes"

	"github.com/projectrekor/rekor/pkg/types"

	"github.com/projectrekor/rekor/pkg/log"

	"github.com/projectrekor/rekor/pkg/generated/models"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/google/trillian/merkle/rfc6962"
	ttypes "github.com/google/trillian/types"
	"github.com/projectrekor/rekor/pkg/generated/restapi/operations/entries"
)

func GetLogEntryByIndexHandler(params entries.GetLogEntryByIndexParams) middleware.Responder {
	api, _ := NewAPI()

	server := serverInstance(api.logClient, api.tLogID)
	indexes := []int64{params.LogIndex}
	resp, err := server.getLeafByIndex(api.tLogID, indexes)
	if err != nil {
		return entries.NewGetLogEntryByIndexDefault(http.StatusInternalServerError).WithPayload(errorMsg("title", "type", err.Error(), http.StatusInternalServerError))
	}

	leaves := resp.getLeafByIndexResult.GetLeaves()
	if len(leaves) > 1 {
		return entries.NewGetLogEntryByIndexDefault(http.StatusInternalServerError).WithPayload(errorMsg("title", "type", err.Error(), http.StatusInternalServerError))
	} else if len(leaves) == 0 {
		return entries.NewGetLogEntryByIndexNotFound()
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
		log.RequestIDLogger(params.HTTPRequest).Error(err)
		return entries.NewCreateLogEntryBadRequest()
	}

	leaf, err := entry.Canonicalize(params.HTTPRequest.Context())
	if err != nil {
		log.RequestIDLogger(params.HTTPRequest).Error(err)
		return entries.NewCreateLogEntryDefault(http.StatusInternalServerError)
	}

	api, _ := NewAPI()
	server := serverInstance(api.logClient, api.tLogID)
	resp, err := server.addLeaf(leaf, api.tLogID)
	if err != nil {
		log.RequestIDLogger(params.HTTPRequest).Error(err)
		return entries.NewCreateLogEntryDefault(http.StatusInternalServerError)
	}
	if resp.status == codes.AlreadyExists || resp.status == codes.FailedPrecondition {
		return entries.NewCreateLogEntryConflict()
	} else if resp.status != codes.OK {
		return entries.NewCreateLogEntryDefault(http.StatusInternalServerError)
	}

	queuedLeaf := resp.getAddResult.QueuedLeaf.Leaf

	uuid := hex.EncodeToString(queuedLeaf.GetMerkleLeafHash())

	logEntry := models.LogEntry{
		uuid: models.LogEntryAnon{
			LogIndex: swag.Int64(queuedLeaf.GetLeafIndex()), //TODO: this comes back 0 from QueueLeafRequest; do we need to re-fetch it before returning?
			Body:     queuedLeaf.GetLeafValue(),
		},
	}

	location := strfmt.URI(fmt.Sprintf("%v/%v", params.HTTPRequest.URL, uuid))
	return entries.NewCreateLogEntryCreated().WithPayload(logEntry).WithLocation(location)
}

func GetLogEntryByUUIDHandler(params entries.GetLogEntryByUUIDParams) middleware.Responder {
	api, _ := NewAPI()
	server := serverInstance(api.logClient, api.tLogID)
	hashValue, _ := hex.DecodeString(params.EntryUUID)
	hashes := [][]byte{hashValue}
	resp, err := server.getLeafByHash(hashes, api.tLogID)
	if err != nil {
		log.RequestIDLogger(params.HTTPRequest).Error(err)
		return entries.NewGetLogEntryByUUIDDefault(http.StatusInternalServerError)
	}

	leaves := resp.getLeafResult.GetLeaves()
	if len(leaves) > 1 {
		return entries.NewGetLogEntryByUUIDDefault(http.StatusInternalServerError).WithPayload(errorMsg("title", "type", err.Error(), http.StatusInternalServerError))
	} else if len(leaves) == 0 {
		return entries.NewGetLogEntryByUUIDNotFound()
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
	api, _ := NewAPI()
	server := serverInstance(api.logClient, api.tLogID)
	hashValue, _ := hex.DecodeString(params.EntryUUID)
	resp, err := server.getProofByHash(hashValue, api.tLogID)
	if err != nil {
		log.RequestIDLogger(params.HTTPRequest).Error(err)
		return entries.NewGetLogEntryProofDefault(http.StatusInternalServerError)
	}

	var root ttypes.LogRootV1
	if err := root.UnmarshalBinary(resp.getProofResult.SignedLogRoot.LogRoot); err != nil {
		return entries.NewGetLogEntryProofDefault(http.StatusInternalServerError).WithPayload(errorMsg("title", "type", err.Error(), http.StatusInternalServerError))
	}

	if len(resp.getProofResult.Proof) != 1 {
		return entries.NewGetLogEntryProofDefault(http.StatusInternalServerError).WithPayload(errorMsg("title", "type", err.Error(), http.StatusInternalServerError))
	}
	proof := resp.getProofResult.Proof[0]

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
	api, _ := NewAPI()
	server := serverInstance(api.logClient, api.tLogID)

	//TODO: parallelize this into different goroutines to speed up search
	searchHashes := [][]byte{}
	if len(params.Entry.EntryUUIDs) > 0 || len(params.Entry.Entries()) > 0 {
		for _, uuid := range params.Entry.EntryUUIDs {
			hash, err := hex.DecodeString(uuid)
			if err != nil {
				return entries.NewSearchLogQueryDefault(http.StatusBadRequest)
			}
			searchHashes = append(searchHashes, hash)
		}

		for _, e := range params.Entry.Entries() {
			entry, err := types.NewEntry(e)
			if err != nil {
				log.RequestIDLogger(params.HTTPRequest).Error(err)
				return entries.NewSearchLogQueryDefault(http.StatusBadRequest)
			}

			if entry.HasExternalEntities() {
				if err := entry.FetchExternalEntities(params.HTTPRequest.Context()); err != nil {
					log.RequestIDLogger(params.HTTPRequest).Error(err)
					return entries.NewSearchLogQueryDefault(http.StatusInternalServerError)
				}
			}

			leaf, err := entry.Canonicalize(params.HTTPRequest.Context())
			if err != nil {
				log.RequestIDLogger(params.HTTPRequest).Error(err)
				return entries.NewSearchLogQueryDefault(http.StatusInternalServerError)
			}
			hasher := rfc6962.DefaultHasher
			leafHash := hasher.HashLeaf(leaf)
			searchHashes = append(searchHashes, leafHash)
		}

		resp, err := server.getLeafByHash(searchHashes, api.tLogID)
		if err != nil {
			return entries.NewSearchLogQueryDefault(http.StatusInternalServerError)
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
		resp, err := server.getLeafByIndex(api.tLogID, params.Entry.LogIndexes)
		if err != nil {
			return entries.NewSearchLogQueryDefault(http.StatusInternalServerError)
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
