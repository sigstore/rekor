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
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag/conv"
	"github.com/google/trillian/types"
	"github.com/spf13/viper"
	"google.golang.org/grpc/codes"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/tlog"
	"github.com/sigstore/rekor/pkg/util"
)

// GetLogInfoHandler returns the current size of the tree and the STH
func GetLogInfoHandler(params tlog.GetLogInfoParams) middleware.Responder {
	ctx := params.HTTPRequest.Context()
	tc, err := api.trillianClientManager.GetTrillianClient(api.ActiveTreeID())
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, err, trillianCommunicationError)
	}

	// for each inactive shard, get the loginfo
	var inactiveShards []*models.InactiveShardLogInfo
	for _, shard := range api.logRanges.GetInactive() {
		// Get details for this inactive shard
		is, err := inactiveShardLogInfo(ctx, shard.TreeID, api.cachedCheckpoints)
		if err != nil {
			return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("inactive shard error: %w", err), unexpectedInactiveShardError)
		}
		inactiveShards = append(inactiveShards, is)
	}

	resp := tc.GetLatest(ctx, 0)
	if resp.Status != codes.OK {
		return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("grpc error: %w", resp.Err), trillianCommunicationError)
	}
	result := resp.GetLatestResult

	root := &types.LogRootV1{}
	if err := root.UnmarshalBinary(result.SignedLogRoot.LogRoot); err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, err, trillianUnexpectedResult)
	}

	hashString := hex.EncodeToString(root.RootHash)
	treeSize := int64(root.TreeSize) //nolint:gosec

	scBytes, err := util.CreateAndSignCheckpoint(ctx,
		viper.GetString("rekor_server.hostname"), api.logRanges.GetActive().TreeID, root.TreeSize, root.RootHash, api.logRanges.GetActive().Signer)
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, err, sthGenerateError)
	}

	logInfo := models.LogInfo{
		RootHash:       &hashString,
		TreeSize:       &treeSize,
		SignedTreeHead: stringPointer(string(scBytes)),
		TreeID:         stringPointer(fmt.Sprintf("%d", api.ActiveTreeID())),
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
		errMsg := fmt.Sprintf(firstSizeLessThanLastSize, *params.FirstSize, params.LastSize)
		return handleRekorAPIError(params, http.StatusBadRequest, fmt.Errorf("consistency proof: %s", errMsg), errMsg)
	}
	ctx := params.HTTPRequest.Context()
	treeID := api.ActiveTreeID()
	if treeIDStr := conv.Value(params.TreeID); treeIDStr != "" {
		id, err := strconv.ParseInt(treeIDStr, 10, 64)
		if err != nil {
			errMsg := fmt.Sprintf("invalid tree ID specified: %s", treeIDStr)
			return handleRekorAPIError(params, http.StatusBadRequest, errors.New(errMsg), errMsg)
		}
		// check if tree ID is valid
		if _, err := api.logRanges.GetLogRangeByTreeID(id); err != nil {
			return handleRekorAPIError(params, http.StatusBadRequest, err, err.Error())
		}
		treeID = id
	}
	tc, err := api.trillianClientManager.GetTrillianClient(treeID)
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, err, trillianCommunicationError)
	}

	resp := tc.GetConsistencyProof(ctx, *params.FirstSize, params.LastSize)
	if resp.Status != codes.OK {
		return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("grpc error: %w", resp.Err), trillianCommunicationError)
	}
	result := resp.GetConsistencyProofResult

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
		err := fmt.Errorf(lastSizeGreaterThanKnown, params.LastSize, root.TreeSize)
		return handleRekorAPIError(params, http.StatusBadRequest, err, err.Error())
	}

	consistencyProof := models.ConsistencyProof{
		RootHash: &hashString,
		Hashes:   proofHashes,
	}

	return tlog.NewGetLogProofOK().WithPayload(&consistencyProof)
}

func inactiveShardLogInfo(ctx context.Context, tid int64, cachedCheckpoints map[int64]string) (*models.InactiveShardLogInfo, error) {
	tc, err := api.trillianClientManager.GetTrillianClient(tid)
	if err != nil {
		return nil, fmt.Errorf("getting log client for tree %d: %w", tid, err)
	}
	resp := tc.GetLatest(ctx, 0)
	if resp.Status != codes.OK {
		return nil, fmt.Errorf("resp code is %d", resp.Status)
	}
	result := resp.GetLatestResult

	root := &types.LogRootV1{}
	if err := root.UnmarshalBinary(result.SignedLogRoot.LogRoot); err != nil {
		return nil, err
	}

	hashString := hex.EncodeToString(root.RootHash)
	treeSize := int64(root.TreeSize) //nolint:gosec

	m := models.InactiveShardLogInfo{
		RootHash:       &hashString,
		TreeSize:       &treeSize,
		TreeID:         stringPointer(fmt.Sprintf("%d", tid)),
		SignedTreeHead: stringPointer(cachedCheckpoints[tid]),
	}
	return &m, nil
}

// handlers for APIs that may be disabled in a given instance

func GetLogInfoNotImplementedHandler(_ tlog.GetLogInfoParams) middleware.Responder {
	err := &models.Error{
		Code:    http.StatusNotImplemented,
		Message: "Get Log Info API not enabled in this Rekor instance",
	}

	return tlog.NewGetLogInfoDefault(http.StatusNotImplemented).WithPayload(err)
}

func GetLogProofNotImplementedHandler(_ tlog.GetLogProofParams) middleware.Responder {
	err := &models.Error{
		Code:    http.StatusNotImplemented,
		Message: "Get Log Proof API not enabled in this Rekor instance",
	}

	return tlog.NewGetLogProofDefault(http.StatusNotImplemented).WithPayload(err)
}
