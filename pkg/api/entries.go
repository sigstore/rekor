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
	"net/http"

	"google.golang.org/grpc/codes"

	"github.com/projectrekor/rekor/pkg/types"

	"github.com/projectrekor/rekor/pkg/log"

	"github.com/projectrekor/rekor/pkg/generated/models"

	"github.com/go-openapi/runtime/middleware"
	ttypes "github.com/google/trillian/types"
	"github.com/projectrekor/rekor/pkg/generated/restapi/operations/entries"
)

func GetLogEntryByIndexHandler(params entries.GetLogEntryByIndexParams) middleware.Responder {
	api, _ := NewAPI()

	server := serverInstance(api.logClient, api.tLogID)
	resp, err := server.getLeafByIndex(api.tLogID, params.LogIndex)
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

	if entry.HasExternalEntities() {
		if err := entry.FetchExternalEntities(); err != nil {
			log.RequestIDLogger(params.HTTPRequest).Error(err)
			return entries.NewCreateLogEntryDefault(http.StatusInternalServerError)
		}
	}

	leaf, err := entry.CanonicalLeaf()
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
	logIndex := queuedLeaf.GetLeafIndex()

	logEntry := models.LogEntry{
		uuid: models.LogEntryAnon{
			LogIndex: &logIndex, //TODO: this comes back 0 from QueueLeafRequest; do we need to re-fetch it before returning?
			Body:     queuedLeaf.GetLeafValue(),
		},
	}
	return entries.NewCreateLogEntryCreated().WithPayload(logEntry)
}

func GetLogEntryByUUIDHandler(params entries.GetLogEntryByUUIDParams) middleware.Responder {
	api, _ := NewAPI()
	server := serverInstance(api.logClient, api.tLogID)
	hashValue, _ := hex.DecodeString(params.EntryUUID)
	resp, err := server.getLeafByHash(hashValue, api.tLogID)
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
	logIndex := leaf.GetLeafIndex()

	logEntry := models.LogEntry{
		uuid: models.LogEntryAnon{
			LogIndex: &logIndex,
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

	hashString := hex.EncodeToString(root.RootHash)
	treeSize := int64(root.TreeSize)

	if len(resp.getProofResult.Proof) != 1 {
		return entries.NewGetLogEntryProofDefault(http.StatusInternalServerError).WithPayload(errorMsg("title", "type", err.Error(), http.StatusInternalServerError))
	}
	proof := resp.getProofResult.Proof[0]

	logIndex := proof.GetLeafIndex()
	hashes := []string{}

	for _, hash := range proof.Hashes {
		hashes = append(hashes, hex.EncodeToString(hash))
	}

	inclusionProof := models.InclusionProof{
		TreeSize: &treeSize,
		RootHash: &hashString,
		LogIndex: &logIndex,
		Hashes:   hashes,
	}
	return entries.NewGetLogEntryProofOK().WithPayload(&inclusionProof)
}

func SearchLogQueryHandler(params entries.SearchLogQueryParams) middleware.Responder {
	return middleware.NotImplemented("operation entries.SearchLogQuery has not yet been implemented")
}
