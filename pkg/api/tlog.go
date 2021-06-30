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
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/go-openapi/runtime/middleware"
	"github.com/google/trillian/types"
	"github.com/spf13/viper"
	"golang.org/x/mod/sumdb/note"
	"google.golang.org/grpc/codes"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/tlog"
	"github.com/sigstore/rekor/pkg/util"
)

// GetLogInfoHandler returns the current size of the tree and the STH
func GetLogInfoHandler(params tlog.GetLogInfoParams) middleware.Responder {
	tc := NewTrillianClient(params.HTTPRequest.Context())

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

	sth := util.RekorSTH{
		SignedNote: util.SignedNote{
			Note: &util.Checkpoint{
				Ecosystem: "Rekor",
				Size:      root.TreeSize,
				Hash:      root.RootHash,
			},
		},
	}
	sth.SetTimestamp(uint64(time.Now().UnixNano()))
	// TODO: once api.signer implements crypto.Signer, switch to using Sign() API on Checkpoint

	// sign the log root ourselves to get the log root signature
	cpString, _ := sth.Note.MarshalText()
	sig, _, err := api.signer.Sign(params.HTTPRequest.Context(), []byte(cpString))
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("signing error: %w", err), signingError)
	}

	sth.Signatures = append(sth.Signatures, note.Signature{
		Name:   viper.GetString("rekor_server.hostname"),
		Hash:   binary.BigEndian.Uint32([]byte(api.pubkeyHash)[0:4]),
		Base64: base64.StdEncoding.EncodeToString(sig),
	})

	scBytes, err := sth.MarshalText()
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("marshalling error: %w", err), sthGenerateError)
	}
	scString := string(scBytes)

	logInfo := models.LogInfo{
		RootHash:       &hashString,
		TreeSize:       &treeSize,
		SignedTreeHead: &scString,
	}
	return tlog.NewGetLogInfoOK().WithPayload(&logInfo)
}

// GetLogProofHandler returns information required to compute a consistency proof between two snapshots of log
func GetLogProofHandler(params tlog.GetLogProofParams) middleware.Responder {
	if *params.FirstSize > params.LastSize {
		return handleRekorAPIError(params, http.StatusBadRequest, nil, fmt.Sprintf(firstSizeLessThanLastSize, *params.FirstSize, params.LastSize))
	}
	tc := NewTrillianClient(params.HTTPRequest.Context())

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
