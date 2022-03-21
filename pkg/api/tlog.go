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

package api

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"
	"github.com/google/trillian/types"
	"github.com/spf13/viper"
	"google.golang.org/grpc/codes"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/tlog"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

// GetLogInfoHandler returns the current size of the tree and the STH
func GetLogInfoHandler(params tlog.GetLogInfoParams) middleware.Responder {
	tc := NewTrillianClient(params.HTTPRequest.Context())

	// for each inactive shard, get the loginfo
	var inactiveShards []*models.InactiveShardLogInfo
	for _, shard := range tc.ranges.GetInactive() {
		if shard.TreeID == tc.ranges.ActiveTreeID() {
			break
		}
		// Get details for this inactive shard
		is, err := inactiveShardLogInfo(params.HTTPRequest.Context(), shard.TreeID)
		if err != nil {
			return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("inactive shard error: %w", err), unexpectedInactiveShardError)
		}
		inactiveShards = append(inactiveShards, is)
	}

	resp := tc.getLatest(0)
	if resp.status != codes.OK {
		return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("grpc error: %w", resp.err), trillianCommunicationError)
	}
	result := resp.getLatestResult

	root := &types.LogRootV1{}
	if err := root.UnmarshalBinary(result.SignedLogRoot.LogRoot); err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, err, trillianUnexpectedResult)
	}

	hashString := hex.EncodeToString(root.RootHash)
	treeSize := int64(root.TreeSize)

	sth, err := util.CreateSignedCheckpoint(util.Checkpoint{
		Origin: "Rekor",
		Size:   root.TreeSize,
		Hash:   root.RootHash,
	})
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("marshalling error: %w", err), sthGenerateError)
	}
	sth.SetTimestamp(uint64(time.Now().UnixNano()))

	// sign the log root ourselves to get the log root signature
	_, err = sth.Sign(viper.GetString("rekor_server.hostname"), api.signer, options.WithContext(params.HTTPRequest.Context()))
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("signing error: %w", err), signingError)
	}

	scBytes, err := sth.SignedNote.MarshalText()
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("marshalling error: %w", err), sthGenerateError)
	}
	scString := string(scBytes)

	logInfo := models.LogInfo{
		RootHash:       &hashString,
		TreeSize:       &treeSize,
		SignedTreeHead: &scString,
		TreeID:         stringPointer(fmt.Sprintf("%d", tc.logID)),
		InactiveShards: inactiveShards,
	}

	return tlog.NewGetLogInfoOK().WithPayload(&logInfo)
}

func stringPointer(s string) *string {
	return &s
}

// GetLogProofHandler returns information required to compute a consistency proof between two snapshots of log
func GetLogProofHandler(params tlog.GetLogProofParams) middleware.Responder {
	if *params.FirstSize > params.LastSize {
		return handleRekorAPIError(params, http.StatusBadRequest, nil, fmt.Sprintf(firstSizeLessThanLastSize, *params.FirstSize, params.LastSize))
	}
	tc := NewTrillianClient(params.HTTPRequest.Context())
	if treeID := swag.StringValue(params.TreeID); treeID != "" {
		id, err := strconv.Atoi(treeID)
		if err != nil {
			log.Logger.Infof("Unable to convert %s to string, skipping initializing client with Tree ID: %v", treeID, err)
		} else {
			tc = NewTrillianClientFromTreeID(params.HTTPRequest.Context(), int64(id))
		}
	}

	resp := tc.getConsistencyProof(*params.FirstSize, params.LastSize)
	if resp.status != codes.OK {
		return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("grpc error: %w", resp.err), trillianCommunicationError)
	}
	result := resp.getConsistencyProofResult

	var root types.LogRootV1
	if err := root.UnmarshalBinary(result.SignedLogRoot.LogRoot); err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, err, trillianUnexpectedResult)
	}

	hashString := hex.EncodeToString(root.RootHash)
	proofHashes := []string{}

	if proof := result.GetProof(); proof != nil {
		for _, hash := range proof.Hashes {
			proofHashes = append(proofHashes, hex.EncodeToString(hash))
		}
	} else {
		// The proof field may be empty if the requested tree_size was larger than that available at the server
		// (e.g. because there is skew between server instances, and an earlier client request was processed by
		// a more up-to-date instance). root.TreeSize is the maximum size currently observed
		return handleRekorAPIError(params, http.StatusBadRequest, nil, fmt.Sprintf(lastSizeGreaterThanKnown, params.LastSize, root.TreeSize))
	}

	consistencyProof := models.ConsistencyProof{
		RootHash: &hashString,
		Hashes:   proofHashes,
	}

	return tlog.NewGetLogProofOK().WithPayload(&consistencyProof)
}

func inactiveShardLogInfo(ctx context.Context, tid int64) (*models.InactiveShardLogInfo, error) {
	tc := NewTrillianClientFromTreeID(ctx, tid)
	resp := tc.getLatest(0)
	if resp.status != codes.OK {
		return nil, fmt.Errorf("resp code is %d", resp.status)
	}
	result := resp.getLatestResult

	root := &types.LogRootV1{}
	if err := root.UnmarshalBinary(result.SignedLogRoot.LogRoot); err != nil {
		return nil, err
	}

	hashString := hex.EncodeToString(root.RootHash)
	treeSize := int64(root.TreeSize)

	sth, err := util.CreateSignedCheckpoint(util.Checkpoint{
		Origin: "Rekor",
		Size:   root.TreeSize,
		Hash:   root.RootHash,
	})
	if err != nil {
		return nil, err
	}
	sth.SetTimestamp(uint64(time.Now().UnixNano()))

	// sign the log root ourselves to get the log root signature
	if _, err := sth.Sign(viper.GetString("rekor_server.hostname"), api.signer, options.WithContext(ctx)); err != nil {
		return nil, err
	}

	scBytes, err := sth.SignedNote.MarshalText()
	if err != nil {
		return nil, err
	}
	m := models.InactiveShardLogInfo{
		RootHash:       &hashString,
		TreeSize:       &treeSize,
		TreeID:         stringPointer(fmt.Sprintf("%d", tid)),
		SignedTreeHead: stringPointer(string(scBytes)),
	}
	return &m, nil
}
