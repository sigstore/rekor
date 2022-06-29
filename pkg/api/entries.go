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
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/google/trillian"
	ttypes "github.com/google/trillian/types"
	"github.com/spf13/viper"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/sync/errgroup"
	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/grpc/codes"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/entries"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

func signEntry(ctx context.Context, signer signature.Signer, entry models.LogEntryAnon) ([]byte, error) {
	payload, err := entry.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshalling error: %v", err)
	}
	canonicalized, err := jsoncanonicalizer.Transform(payload)
	if err != nil {
		return nil, fmt.Errorf("canonicalizing error: %v", err)
	}
	signature, err := signer.SignMessage(bytes.NewReader(canonicalized), options.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("signing error: %v", err)
	}
	return signature, nil
}

// logEntryFromLeaf creates a signed LogEntry struct from trillian structs
func logEntryFromLeaf(ctx context.Context, signer signature.Signer, tc TrillianClient, leaf *trillian.LogLeaf,
	signedLogRoot *trillian.SignedLogRoot, proof *trillian.Proof, tid int64, ranges sharding.LogRanges) (models.LogEntry, error) {

	root := &ttypes.LogRootV1{}
	if err := root.UnmarshalBinary(signedLogRoot.LogRoot); err != nil {
		return nil, err
	}
	hashes := []string{}
	for _, hash := range proof.Hashes {
		hashes = append(hashes, hex.EncodeToString(hash))
	}

	virtualIndex := sharding.VirtualLogIndex(leaf.GetLeafIndex(), tid, ranges)
	logEntryAnon := models.LogEntryAnon{
		LogID:          swag.String(api.pubkeyHash),
		LogIndex:       &virtualIndex,
		Body:           leaf.LeafValue,
		IntegratedTime: swag.Int64(leaf.IntegrateTimestamp.AsTime().Unix()),
	}

	signature, err := signEntry(ctx, signer, logEntryAnon)
	if err != nil {
		return nil, fmt.Errorf("signing entry error: %w", err)
	}

	inclusionProof := models.InclusionProof{
		TreeSize: swag.Int64(int64(root.TreeSize)),
		RootHash: swag.String(hex.EncodeToString(root.RootHash)),
		LogIndex: swag.Int64(proof.GetLeafIndex()),
		Hashes:   hashes,
	}

	uuid := hex.EncodeToString(leaf.MerkleLeafHash)
	if viper.GetBool("enable_attestation_storage") {
		pe, err := models.UnmarshalProposedEntry(bytes.NewReader(leaf.LeafValue), runtime.JSONConsumer())
		if err != nil {
			return nil, err
		}
		eimpl, err := types.NewEntry(pe)
		if err != nil {
			return nil, err
		}

		var att []byte
		var fetchErr error
		attKey := eimpl.AttestationKey()
		// if we're given a key by the type logic, let's try that first
		if attKey != "" {
			att, fetchErr = storageClient.FetchAttestation(ctx, attKey)
			if fetchErr != nil {
				log.Logger.Errorf("error fetching attestation by key, trying by UUID: %s %w", attKey, fetchErr)
			}
		}
		// if looking up by key failed or we weren't able to generate a key, try looking up by uuid
		if attKey == "" || fetchErr != nil {
			activeTree := fmt.Sprintf("%x", tc.logID)
			entryIDstruct, err := sharding.CreateEntryIDFromParts(activeTree, uuid)
			if err != nil {
				return nil, fmt.Errorf("error creating EntryID from active treeID %v and uuid %v: %w", activeTree, uuid, err)
			}
			att, fetchErr = storageClient.FetchAttestation(ctx, entryIDstruct.UUID)
			if fetchErr != nil {
				log.Logger.Errorf("error fetching attestation by uuid: %s %v", entryIDstruct.UUID, fetchErr)
			}
		}
		if fetchErr == nil {
			logEntryAnon.Attestation = &models.LogEntryAnonAttestation{
				Data: att,
			}
		}
	}

	logEntryAnon.Verification = &models.LogEntryAnonVerification{
		InclusionProof:       &inclusionProof,
		SignedEntryTimestamp: strfmt.Base64(signature),
	}

	return models.LogEntry{
		uuid: logEntryAnon}, nil
}

// GetLogEntryAndProofByIndexHandler returns the entry and inclusion proof for a specified log index
func GetLogEntryByIndexHandler(params entries.GetLogEntryByIndexParams) middleware.Responder {
	ctx := params.HTTPRequest.Context()
	tid, resolvedIndex := api.logRanges.ResolveVirtualIndex(int(params.LogIndex))
	tc := NewTrillianClientFromTreeID(ctx, tid)
	log.RequestIDLogger(params.HTTPRequest).Debugf("Retrieving resolved index %v from TreeID %v", resolvedIndex, tid)

	resp := tc.getLeafAndProofByIndex(resolvedIndex)
	switch resp.status {
	case codes.OK:
	case codes.NotFound, codes.OutOfRange, codes.InvalidArgument:
		return handleRekorAPIError(params, http.StatusNotFound, fmt.Errorf("grpc error: %w", resp.err), "")
	default:
		return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("grpc err: %w", resp.err), trillianCommunicationError)
	}

	result := resp.getLeafAndProofResult
	leaf := result.Leaf
	if leaf == nil {
		return handleRekorAPIError(params, http.StatusNotFound, errors.New("grpc returned 0 leaves with success code"), "")
	}

	logEntry, err := logEntryFromLeaf(ctx, api.signer, tc, leaf, result.SignedLogRoot, result.Proof, tid, api.logRanges)
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, err, err.Error())
	}

	return entries.NewGetLogEntryByIndexOK().WithPayload(logEntry)
}

func createLogEntry(params entries.CreateLogEntryParams) (models.LogEntry, middleware.Responder) {
	ctx := params.HTTPRequest.Context()
	entry, err := types.NewEntry(params.ProposedEntry)
	if err != nil {
		return nil, handleRekorAPIError(params, http.StatusBadRequest, err, fmt.Sprintf(validationError, err))
	}
	leaf, err := types.CanonicalizeEntry(ctx, entry)
	if err != nil {
		if _, ok := (err).(types.ValidationError); ok {
			return nil, handleRekorAPIError(params, http.StatusBadRequest, err, fmt.Sprintf(validationError, err))
		}
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, err, failedToGenerateCanonicalEntry)
	}

	tc := NewTrillianClient(ctx)

	resp := tc.addLeaf(leaf)
	// this represents overall GRPC response state (not the results of insertion into the log)
	if resp.status != codes.OK {
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("grpc error: %w", resp.err), trillianUnexpectedResult)
	}

	// this represents the results of inserting the proposed leaf into the log; status is nil in success path
	insertionStatus := resp.getAddResult.QueuedLeaf.Status
	if insertionStatus != nil {
		switch insertionStatus.Code {
		case int32(code.Code_OK):
		case int32(code.Code_ALREADY_EXISTS), int32(code.Code_FAILED_PRECONDITION):
			existingUUID := hex.EncodeToString(rfc6962.DefaultHasher.HashLeaf(leaf))
			err := fmt.Errorf("grpc error: %v", insertionStatus.String())
			return nil, handleRekorAPIError(params, http.StatusConflict, err, fmt.Sprintf(entryAlreadyExists, existingUUID), "entryURL", getEntryURL(*params.HTTPRequest.URL, existingUUID))
		default:
			err := fmt.Errorf("grpc error: %v", insertionStatus.String())
			return nil, handleRekorAPIError(params, http.StatusInternalServerError, err, trillianUnexpectedResult)
		}
	}

	// We made it this far, that means the entry was successfully added.
	metricNewEntries.Inc()

	queuedLeaf := resp.getAddResult.QueuedLeaf.Leaf

	uuid := hex.EncodeToString(queuedLeaf.GetMerkleLeafHash())
	activeTree := fmt.Sprintf("%x", tc.logID)
	entryIDstruct, err := sharding.CreateEntryIDFromParts(activeTree, uuid)
	if err != nil {
		err := fmt.Errorf("error creating EntryID from active treeID %v and uuid %v: %w", activeTree, uuid, err)
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, err, fmt.Sprintf(validationError, err))
	}
	entryID := entryIDstruct.ReturnEntryIDString()

	// The log index should be the virtual log index across all shards
	virtualIndex := sharding.VirtualLogIndex(queuedLeaf.LeafIndex, api.logRanges.ActiveTreeID(), api.logRanges)
	logEntryAnon := models.LogEntryAnon{
		LogID:          swag.String(api.pubkeyHash),
		LogIndex:       swag.Int64(virtualIndex),
		Body:           queuedLeaf.GetLeafValue(),
		IntegratedTime: swag.Int64(queuedLeaf.IntegrateTimestamp.AsTime().Unix()),
	}

	if viper.GetBool("enable_retrieve_api") {
		go func() {
			keys, err := entry.IndexKeys()
			if err != nil {
				log.RequestIDLogger(params.HTTPRequest).Error(err)
				return
			}
			for _, key := range keys {
				if err := addToIndex(context.Background(), key, entryID); err != nil {
					log.RequestIDLogger(params.HTTPRequest).Error(err)
				}
			}
		}()
	}

	if viper.GetBool("enable_attestation_storage") {

		go func() {
			attKey, attVal := entry.AttestationKeyValue()
			if attVal == nil {
				log.RequestIDLogger(params.HTTPRequest).Infof("no attestation for %s", uuid)
				return
			}
			if err := storeAttestation(context.Background(), attKey, attVal); err != nil {
				// entryIDstruct.UUID
				log.RequestIDLogger(params.HTTPRequest).Errorf("error storing attestation: %s", err)
			} else {
				log.RequestIDLogger(params.HTTPRequest).Infof("stored attestation for uuid %s with filename %s", entryIDstruct.UUID, attKey)
			}
		}()
	}

	signature, err := signEntry(ctx, api.signer, logEntryAnon)
	if err != nil {
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("signing entry error: %v", err), signingError)
	}

	logEntryAnon.Verification = &models.LogEntryAnonVerification{
		SignedEntryTimestamp: strfmt.Base64(signature),
	}

	logEntry := models.LogEntry{
		uuid: logEntryAnon,
	}
	return logEntry, nil
}

// CreateLogEntryHandler creates new entry into log
func CreateLogEntryHandler(params entries.CreateLogEntryParams) middleware.Responder {
	httpReq := params.HTTPRequest

	logEntry, err := createLogEntry(params)
	if err != nil {
		return err
	}

	var uuid string
	for location := range logEntry {
		uuid = location
	}

	return entries.NewCreateLogEntryCreated().WithPayload(logEntry).WithLocation(getEntryURL(*httpReq.URL, uuid)).WithETag(uuid)
}

// getEntryURL returns the absolute path to the log entry in a RESTful style
func getEntryURL(locationURL url.URL, uuid string) strfmt.URI {
	// remove API key from output
	query := locationURL.Query()
	query.Del("apiKey")
	locationURL.RawQuery = query.Encode()
	locationURL.Path = fmt.Sprintf("%v/%v", locationURL.Path, uuid)
	return strfmt.URI(locationURL.String())

}

// GetLogEntryByUUIDHandler gets log entry and inclusion proof for specified UUID aka merkle leaf hash
func GetLogEntryByUUIDHandler(params entries.GetLogEntryByUUIDParams) middleware.Responder {
	uuid, err := sharding.GetUUIDFromIDString(params.EntryUUID)
	if err != nil {
		return handleRekorAPIError(params, http.StatusBadRequest, err, fmt.Sprintf("could not get UUID from ID string %v", params.EntryUUID))
	}
	tidString, err := sharding.GetTreeIDFromIDString(params.EntryUUID)

	// If treeID is found in EntryID, route to correct tree
	if err == nil {
		tid, err := strconv.ParseInt(tidString, 16, 64)
		if err != nil {
			return handleRekorAPIError(params, http.StatusBadRequest, err, fmt.Sprintf("could not convert treeID %v to int", tidString))
		}
		logEntry, err := RetrieveUUID(params, uuid, tid)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return handleRekorAPIError(params, http.StatusNotFound, err, "")
			}
			return handleRekorAPIError(params, http.StatusInternalServerError, err, "")
		}
		return entries.NewGetLogEntryByUUIDOK().WithPayload(logEntry)
	}

	// If EntryID is plain UUID (ex. from client v0.5), check all trees
	if errors.Is(err, sharding.ErrPlainUUID) {
		trees := []sharding.LogRange{{TreeID: api.logRanges.ActiveTreeID()}}
		trees = append(trees, api.logRanges.GetInactive()...)

		for _, t := range trees {
			logEntry, err := RetrieveUUID(params, uuid, t.TreeID)
			if err != nil {
				continue
			}
			return entries.NewGetLogEntryByUUIDOK().WithPayload(logEntry)
		}
		return handleRekorAPIError(params, http.StatusNotFound, err, "UUID not found in any known trees")
	}
	return handleRekorAPIError(params, http.StatusBadRequest, err, fmt.Sprintf("could not get treeID from ID string %v", params.EntryUUID))
}

// SearchLogQueryHandler searches log by index, UUID, or proposed entry and returns array of entries found with inclusion proofs
func SearchLogQueryHandler(params entries.SearchLogQueryParams) middleware.Responder {
	httpReqCtx := params.HTTPRequest.Context()
	resultPayload := []models.LogEntry{}
	tc := NewTrillianClient(httpReqCtx)

	if len(params.Entry.EntryUUIDs) > 0 || len(params.Entry.Entries()) > 0 {
		g, _ := errgroup.WithContext(httpReqCtx)

		var searchHashes [][]byte
		for _, entryID := range params.Entry.EntryUUIDs {
			uuid, err := sharding.GetUUIDFromIDString(entryID)
			if err != nil {
				return handleRekorAPIError(params, http.StatusBadRequest, err, fmt.Sprintf("could not get UUID from ID string %v", entryID))
			}
			if tid, err := sharding.TreeID(entryID); err == nil {
				entry, err := RetrieveUUID(entries.GetLogEntryByUUIDParams{
					EntryUUID:   entryID,
					HTTPRequest: params.HTTPRequest,
				}, uuid, tid)
				if err != nil {
					return handleRekorAPIError(params, http.StatusBadRequest, err, fmt.Sprintf("could not get uuid from %v", entryID))
				}
				resultPayload = append(resultPayload, entry)
				continue
			}
			hash, err := hex.DecodeString(uuid)
			if err != nil {
				return handleRekorAPIError(params, http.StatusBadRequest, err, malformedUUID)
			}
			searchHashes = append(searchHashes, hash)
		}

		code := http.StatusBadRequest
		for _, e := range params.Entry.Entries() {
			e := e // https://golang.org/doc/faq#closures_and_goroutines
			g.Go(func() error {
				entry, err := types.NewEntry(e)
				if err != nil {
					return err
				}

				leaf, err := types.CanonicalizeEntry(httpReqCtx, entry)
				if err != nil {
					code = http.StatusInternalServerError
					return err
				}
				hasher := rfc6962.DefaultHasher
				leafHash := hasher.HashLeaf(leaf)
				searchHashes = append(searchHashes, leafHash)
				return nil
			})
		}

		if err := g.Wait(); err != nil {
			return handleRekorAPIError(params, code, err, err.Error())
		}

		searchByHashResults := make([]*trillian.GetEntryAndProofResponse, len(searchHashes))
		g, _ = errgroup.WithContext(httpReqCtx)
		for i, hash := range searchHashes {
			i, hash := i, hash // https://golang.org/doc/faq#closures_and_goroutines
			g.Go(func() error {
				resp := tc.getLeafAndProofByHash(hash)
				switch resp.status {
				case codes.OK, codes.NotFound:
				default:
					return resp.err
				}
				leafResult := resp.getLeafAndProofResult
				if leafResult != nil && leafResult.Leaf != nil {
					searchByHashResults[i] = leafResult
				}
				return nil
			})
		}

		if err := g.Wait(); err != nil {
			return handleRekorAPIError(params, code, err, err.Error())
		}

		for _, leafResp := range searchByHashResults {
			if leafResp != nil {
				logEntry, err := logEntryFromLeaf(httpReqCtx, api.signer, tc, leafResp.Leaf, leafResp.SignedLogRoot, leafResp.Proof, api.logRanges.ActiveTreeID(), api.logRanges)
				if err != nil {
					return handleRekorAPIError(params, code, err, err.Error())
				}

				resultPayload = append(resultPayload, logEntry)
			}
		}
	}

	if len(params.Entry.LogIndexes) > 0 {
		g, _ := errgroup.WithContext(httpReqCtx)

		leafResults := make([]*trillian.GetEntryAndProofResponse, len(params.Entry.LogIndexes))
		for i, logIndex := range params.Entry.LogIndexes {
			i, logIndex := i, logIndex // https://golang.org/doc/faq#closures_and_goroutines
			g.Go(func() error {
				tid, resolvedIndex := api.logRanges.ResolveVirtualIndex(int(swag.Int64Value(logIndex)))
				trillianClient := NewTrillianClientFromTreeID(httpReqCtx, tid)
				resp := trillianClient.getLeafAndProofByIndex(resolvedIndex)
				switch resp.status {
				case codes.OK, codes.NotFound:
				default:
					return resp.err
				}
				leafResult := resp.getLeafAndProofResult
				if leafResult != nil && leafResult.Leaf != nil {
					leafResults[i] = leafResult
				}
				return nil
			})
		}

		if err := g.Wait(); err != nil {
			return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("grpc error: %w", err), trillianUnexpectedResult)
		}

		for _, result := range leafResults {
			if result != nil {
				logEntry, err := logEntryFromLeaf(httpReqCtx, api.signer, tc, result.Leaf, result.SignedLogRoot, result.Proof, api.logRanges.ActiveTreeID(), api.logRanges)
				if err != nil {
					return handleRekorAPIError(params, http.StatusInternalServerError, err, trillianUnexpectedResult)
				}
				resultPayload = append(resultPayload, logEntry)
			}
		}
	}

	return entries.NewSearchLogQueryOK().WithPayload(resultPayload)
}

var ErrNotFound = errors.New("grpc returned 0 leaves with success code")

// Attempt to retrieve a UUID from a backend tree
func RetrieveUUID(params entries.GetLogEntryByUUIDParams, uuid string, tid int64) (models.LogEntry, error) {
	ctx := params.HTTPRequest.Context()
	hashValue, err := hex.DecodeString(uuid)
	if err != nil {
		return models.LogEntry{}, err
	}

	tc := NewTrillianClientFromTreeID(params.HTTPRequest.Context(), tid)
	log.RequestIDLogger(params.HTTPRequest).Debugf("Attempting to retrieve UUID %v from TreeID %v", uuid, tid)

	resp := tc.getLeafAndProofByHash(hashValue)
	switch resp.status {
	case codes.OK:
		result := resp.getLeafAndProofResult
		leaf := result.Leaf
		if leaf == nil {
			return models.LogEntry{}, ErrNotFound
		}

		logEntry, err := logEntryFromLeaf(ctx, api.signer, tc, leaf, result.SignedLogRoot, result.Proof, tid, api.logRanges)
		if err != nil {
			return models.LogEntry{}, errors.New("could not create log entry from leaf")
		}
		return logEntry, nil

	case codes.NotFound:
		return models.LogEntry{}, ErrNotFound
	default:
		return models.LogEntry{}, errors.New("unexpected error")
	}
}
