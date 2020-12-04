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

	"github.com/projectrekor/rekor/pkg/log"

	"github.com/projectrekor/rekor/pkg/generated/models"

	"github.com/go-openapi/runtime/middleware"
	"github.com/projectrekor/rekor/pkg/generated/restapi/operations/entries"
)

func GetLogEntryByIndexHandler(params entries.GetLogEntryByIndexParams) middleware.Responder {
	api, _ := NewAPI()

	server := serverInstance(api.logClient, api.tLogID)
	resp, err := server.getLeafByIndex(api.tLogID, params.LogIndex)
	log.RequestIDLogger(params.HTTPRequest).Infof("index requested :%v", params.LogIndex)
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
		},
	}
	return entries.NewGetLogEntryByIndexOK().WithPayload(logEntry)
}

func CreateLogEntryHandler(params entries.CreateLogEntryParams) middleware.Responder {
	return middleware.NotImplemented("operation entries.CreateLogEntry has not yet been implemented")
}

func GetLogEntryByUUIDHandler(params entries.GetLogEntryByUUIDParams) middleware.Responder {
	return middleware.NotImplemented("operation entries.GetLogEntryByUUID has not yet been implemented")
}

func GetLogEntryProofHandler(params entries.GetLogEntryProofParams) middleware.Responder {
	return middleware.NotImplemented("operation entries.GetLogEntryProof has not yet been implemented")
}

func SearchLogQueryHandler(params entries.SearchLogQueryParams) middleware.Responder {
	return middleware.NotImplemented("operation entries.SearchLogQuery has not yet been implemented")
}
