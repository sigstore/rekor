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

	"github.com/projectrekor/rekor/pkg/generated/models"

	"github.com/go-openapi/runtime/middleware"
	"github.com/google/trillian/types"
	"github.com/projectrekor/rekor/pkg/generated/restapi/operations/tlog"
)

func GetLogInfoHandler(params tlog.GetLogInfoParams) middleware.Responder {
	api, _ := NewAPI()

	server := serverInstance(api.logClient, api.tLogID)

	resp, err := server.getLatest(api.tLogID, 0)
	if err != nil {
		return tlog.NewGetLogInfoDefault(http.StatusInternalServerError).WithPayload(errorMsg("title", "type", err.Error(), http.StatusInternalServerError))
	}

	var root types.LogRootV1
	if err := root.UnmarshalBinary(resp.getLatestResult.SignedLogRoot.LogRoot); err != nil {
		return tlog.NewGetLogInfoDefault(http.StatusInternalServerError).WithPayload(errorMsg("title", "type", err.Error(), http.StatusInternalServerError))
	}

	hashString := hex.EncodeToString(root.RootHash)
	treeSize := int64(root.TreeSize)

	logInfo := models.LogInfo{
		RootHash: &hashString,
		TreeSize: &treeSize,
	}

	return tlog.NewGetLogInfoOK().WithPayload(&logInfo)
}

func GetLogProofHandler(params tlog.GetLogProofParams) middleware.Responder {
	if *params.FirstSize > params.LastSize {
		return tlog.NewGetLogProofBadRequest().WithPayload(errorMsg("title", "type", "firstSize must be greater than or equal to lastSize", http.StatusBadRequest))
	}
	api, _ := NewAPI()

	server := serverInstance(api.logClient, api.tLogID)

	resp, err := server.getConsistencyProof(api.tLogID, *params.FirstSize, params.LastSize)
	if err != nil {
		return tlog.NewGetLogProofDefault(http.StatusInternalServerError).WithPayload(errorMsg("title", "type", err.Error(), http.StatusInternalServerError))
	}
	result := resp.getConsistencyProofResult

	var root types.LogRootV1
	if err := root.UnmarshalBinary(result.SignedLogRoot.LogRoot); err != nil {
		return tlog.NewGetLogProofDefault(http.StatusInternalServerError).WithPayload(errorMsg("title", "type", err.Error(), http.StatusInternalServerError))
	}

	hashString := hex.EncodeToString(root.RootHash)
	proofHashes := []string{}

	if proof := result.GetProof(); proof != nil {
		for _, hash := range proof.Hashes {
			proofHashes = append(proofHashes, hex.EncodeToString(hash))
		}
	}

	consistencyProof := models.ConsistencyProof{
		RootHash: &hashString,
		Hashes:   proofHashes,
	}
	return tlog.NewGetLogProofOK().WithPayload(&consistencyProof)
}
