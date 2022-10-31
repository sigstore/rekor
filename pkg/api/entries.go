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
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

const (
	maxSearchQueries = 10
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

	log.ContextLogger(ctx).Debugf("log entry from leaf %d", leaf.GetLeafIndex())
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

	scBytes, err := util.CreateAndSignCheckpoint(ctx, viper.GetString("rekor_server.hostname"), tc.logID, root, api.signer)
	if err != nil {
		return nil, err
	}

	inclusionProof := models.InclusionProof{
		TreeSize:   swag.Int64(int64(root.TreeSize)),
		RootHash:   swag.String(hex.EncodeToString(root.RootHash)),
		LogIndex:   swag.Int64(proof.GetLeafIndex()),
		Hashes:     hashes,
		Checkpoint: stringPointer(string(scBytes)),
	}

	uuid := hex.EncodeToString(leaf.MerkleLeafHash)
	treeID := fmt.Sprintf("%x", tid)
	entryIDstruct, err := sharding.CreateEntryIDFromParts(treeID, uuid)
	if err != nil {
		return nil, fmt.Errorf("error creating EntryID from active treeID %v and uuid %v: %w", treeID, uuid, err)
	}
	entryID := entryIDstruct.ReturnEntryIDString()

	if viper.GetBool("enable_attestation_storage") {
		pe, err := models.UnmarshalProposedEntry(bytes.NewReader(leaf.LeafValue), runtime.JSONConsumer())
		if err != nil {
			return nil, err
		}
		eimpl, err := types.UnmarshalEntry(pe)
		if err != nil {
			return nil, err
		}

		if entryWithAtt, ok := eimpl.(types.EntryWithAttestationImpl); ok {
			var att []byte
			var fetchErr error
			attKey := entryWithAtt.AttestationKey()
			// if we're given a key by the type logic, let's try that first
			if attKey != "" {
				att, fetchErr = storageClient.FetchAttestation(ctx, attKey)
				if fetchErr != nil {
					log.ContextLogger(ctx).Errorf("error fetching attestation by key, trying by UUID: %s %w", attKey, fetchErr)
				}
			}
			// if looking up by key failed or we weren't able to generate a key, try looking up by uuid
			if attKey == "" || fetchErr != nil {
				att, fetchErr = storageClient.FetchAttestation(ctx, entryIDstruct.UUID)
				if fetchErr != nil {
					log.ContextLogger(ctx).Errorf("error fetching attestation by uuid: %s %v", entryIDstruct.UUID, fetchErr)
				}
			}
			if fetchErr == nil {
				logEntryAnon.Attestation = &models.LogEntryAnonAttestation{
					Data: att,
				}
			}
		}
	}

	logEntryAnon.Verification = &models.LogEntryAnonVerification{
		InclusionProof:       &inclusionProof,
		SignedEntryTimestamp: strfmt.Base64(signature),
	}

	return models.LogEntry{
		entryID: logEntryAnon}, nil
}

// GetLogEntryAndProofByIndexHandler returns the entry and inclusion proof for a specified log index
func GetLogEntryByIndexHandler(params entries.GetLogEntryByIndexParams) middleware.Responder {
	ctx := params.HTTPRequest.Context()
	logEntry, err := retrieveLogEntryByIndex(ctx, int(params.LogIndex))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return handleRekorAPIError(params, http.StatusNotFound, fmt.Errorf("grpc error: %w", err), "")
		}
		return handleRekorAPIError(params, http.StatusInternalServerError, err, err.Error())
	}
	return entries.NewGetLogEntryByIndexOK().WithPayload(logEntry)
}

func createLogEntry(params entries.CreateLogEntryParams) (models.LogEntry, middleware.Responder) {
	ctx := params.HTTPRequest.Context()
	entry, err := types.CreateVersionedEntry(params.ProposedEntry)
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

	if redisClient != nil {
		go func() {
			keys, err := entry.IndexKeys()
			if err != nil {
				log.ContextLogger(ctx).Error(err)
				return
			}
			for _, key := range keys {
				if err := addToIndex(context.Background(), key, entryID); err != nil {
					log.ContextLogger(ctx).Error(err)
				}
			}
		}()
	}

	if viper.GetBool("enable_attestation_storage") {
		if entryWithAtt, ok := entry.(types.EntryWithAttestationImpl); ok {
			attKey, attVal := entryWithAtt.AttestationKeyValue()
			if attVal != nil {
				go func() {
					if err := storeAttestation(context.Background(), attKey, attVal); err != nil {
						// entryIDstruct.UUID
						log.ContextLogger(ctx).Errorf("error storing attestation: %s", err)
					} else {
						log.ContextLogger(ctx).Infof("stored attestation for uuid %s with filename %s", entryIDstruct.UUID, attKey)
					}
				}()
			} else {
				log.ContextLogger(ctx).Infof("no attestation returned for %s", uuid)
			}
		}
	}

	signature, err := signEntry(ctx, api.signer, logEntryAnon)
	if err != nil {
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("signing entry error: %v", err), signingError)
	}

	root := &ttypes.LogRootV1{}
	if err := root.UnmarshalBinary(resp.getLeafAndProofResult.SignedLogRoot.LogRoot); err != nil {
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("error unmarshalling log root: %v", err), sthGenerateError)
	}
	hashes := []string{}
	for _, hash := range resp.getLeafAndProofResult.Proof.Hashes {
		hashes = append(hashes, hex.EncodeToString(hash))
	}

	scBytes, err := util.CreateAndSignCheckpoint(ctx, viper.GetString("rekor_server.hostname"), tc.logID, root, api.signer)
	if err != nil {
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, err, sthGenerateError)
	}

	inclusionProof := models.InclusionProof{
		TreeSize:   swag.Int64(int64(root.TreeSize)),
		RootHash:   swag.String(hex.EncodeToString(root.RootHash)),
		LogIndex:   swag.Int64(queuedLeaf.LeafIndex),
		Hashes:     hashes,
		Checkpoint: stringPointer(string(scBytes)),
	}

	logEntryAnon.Verification = &models.LogEntryAnonVerification{
		InclusionProof:       &inclusionProof,
		SignedEntryTimestamp: strfmt.Base64(signature),
	}

	logEntry := models.LogEntry{
		entryID: logEntryAnon,
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
	logEntry, err := retrieveLogEntry(params.HTTPRequest.Context(), params.EntryUUID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return handleRekorAPIError(params, http.StatusNotFound, err, "")
		}
		if _, ok := (err).(types.ValidationError); ok {
			return handleRekorAPIError(params, http.StatusBadRequest, err, fmt.Sprintf("incorrectly formatted uuid %s", params.EntryUUID), params.EntryUUID)
		}
		return handleRekorAPIError(params, http.StatusInternalServerError, err, "ID %s not found in any known trees", params.EntryUUID)
	}
	return entries.NewGetLogEntryByUUIDOK().WithPayload(logEntry)
}

// SearchLogQueryHandler searches log by index, UUID, or proposed entry and returns array of entries found with inclusion proofs
func SearchLogQueryHandler(params entries.SearchLogQueryParams) middleware.Responder {
	httpReqCtx := params.HTTPRequest.Context()
	resultPayload := []models.LogEntry{}

	totalQueries := len(params.Entry.EntryUUIDs) + len(params.Entry.Entries()) + len(params.Entry.LogIndexes)
	if totalQueries > maxSearchQueries {
		return handleRekorAPIError(params, http.StatusUnprocessableEntity, fmt.Errorf(maxSearchQueryLimit, maxSearchQueries), fmt.Sprintf(maxSearchQueryLimit, maxSearchQueries))
	}

	if len(params.Entry.EntryUUIDs) > 0 || len(params.Entry.Entries()) > 0 {
		g, _ := errgroup.WithContext(httpReqCtx)

		var searchHashes [][]byte
		for _, entryID := range params.Entry.EntryUUIDs {
			// if we got this far, then entryID is either a 64 or 80 character hex string
			err := sharding.ValidateEntryID(entryID)
			if err == nil {
				logEntry, err := retrieveLogEntry(httpReqCtx, entryID)
				if err != nil && !errors.Is(err, ErrNotFound) {
					return handleRekorAPIError(params, http.StatusInternalServerError, err, fmt.Sprintf("error getting log entry for %s", entryID))
				} else if err == nil {
					resultPayload = append(resultPayload, logEntry)
				}
				continue
			} else if len(entryID) == sharding.EntryIDHexStringLen {
				// if ValidateEntryID failed and this is a full length entryID, then we can't search for it
				return handleRekorAPIError(params, http.StatusBadRequest, err, fmt.Sprintf("invalid entryID %s", entryID))
			}
			// At this point, check if we got a uuid instead of an EntryID, so search for the hash later
			uuid := entryID
			if err := sharding.ValidateUUID(uuid); err != nil {
				return handleRekorAPIError(params, http.StatusBadRequest, err, fmt.Sprintf("invalid uuid %s", uuid))
			}
			hash, err := hex.DecodeString(uuid)
			if err != nil {
				return handleRekorAPIError(params, http.StatusBadRequest, err, malformedUUID)
			}
			searchHashes = append(searchHashes, hash)
		}

		entries := params.Entry.Entries()
		searchHashesChan := make(chan []byte, len(entries))
		for _, e := range entries {
			e := e // https://golang.org/doc/faq#closures_and_goroutines
			g.Go(func() error {
				entry, err := types.UnmarshalEntry(e)
				if err != nil {
					return fmt.Errorf("unmarshalling entry: %w", err)
				}

				leaf, err := types.CanonicalizeEntry(httpReqCtx, entry)
				if err != nil {
					return fmt.Errorf("canonicalizing entry: %w", err)
				}
				hasher := rfc6962.DefaultHasher
				leafHash := hasher.HashLeaf(leaf)
				searchHashesChan <- leafHash
				return nil
			})
		}

		if err := g.Wait(); err != nil {
			return handleRekorAPIError(params, http.StatusBadRequest, err, err.Error())
		}
		close(searchHashesChan)
		for hash := range searchHashesChan {
			searchHashes = append(searchHashes, hash)
		}

		searchByHashResults := make([]map[int64]*trillian.GetEntryAndProofResponse, len(searchHashes))
		g, _ = errgroup.WithContext(httpReqCtx)
		for i, hash := range searchHashes {
			i, hash := i, hash // https://golang.org/doc/faq#closures_and_goroutines
			g.Go(func() error {
				var results map[int64]*trillian.GetEntryAndProofResponse
				for _, shard := range api.logRanges.AllShards() {
					tcs := NewTrillianClientFromTreeID(httpReqCtx, shard)
					resp := tcs.getLeafAndProofByHash(hash)
					switch resp.status {
					case codes.OK:
						leafResult := resp.getLeafAndProofResult
						if leafResult != nil && leafResult.Leaf != nil {
							if results == nil {
								results = map[int64]*trillian.GetEntryAndProofResponse{}
							}
							results[shard] = resp.getLeafAndProofResult
						}
					case codes.NotFound:
						// do nothing here, do not throw 404 error
						continue
					default:
						log.ContextLogger(httpReqCtx).Errorf("error getLeafAndProofByHash(%s): code: %v, msg %v", hex.EncodeToString(hash), resp.status, resp.err)
						return fmt.Errorf(trillianCommunicationError)
					}
				}
				searchByHashResults[i] = results
				return nil
			})
		}

		if err := g.Wait(); err != nil {
			return handleRekorAPIError(params, http.StatusInternalServerError, err, err.Error())
		}

		for _, hashMap := range searchByHashResults {
			for shard, leafResp := range hashMap {
				if leafResp == nil {
					continue
				}
				tcs := NewTrillianClientFromTreeID(httpReqCtx, shard)
				logEntry, err := logEntryFromLeaf(httpReqCtx, api.signer, tcs, leafResp.Leaf, leafResp.SignedLogRoot, leafResp.Proof, shard, api.logRanges)
				if err != nil {
					return handleRekorAPIError(params, http.StatusInternalServerError, err, err.Error())
				}
				resultPayload = append(resultPayload, logEntry)
			}
		}
	}

	if len(params.Entry.LogIndexes) > 0 {
		g, _ := errgroup.WithContext(httpReqCtx)
		resultPayloadChan := make(chan models.LogEntry, len(params.Entry.LogIndexes))

		for _, logIndex := range params.Entry.LogIndexes {
			logIndex := logIndex // https://golang.org/doc/faq#closures_and_goroutines
			g.Go(func() error {
				logEntry, err := retrieveLogEntryByIndex(httpReqCtx, int(swag.Int64Value(logIndex)))
				if err != nil && !errors.Is(err, ErrNotFound) {
					return err
				} else if err == nil {
					resultPayloadChan <- logEntry
				}
				return nil
			})
		}

		if err := g.Wait(); err != nil {
			return handleRekorAPIError(params, http.StatusInternalServerError, err, err.Error())
		}
		close(resultPayloadChan)
		for result := range resultPayloadChan {
			resultPayload = append(resultPayload, result)
		}
	}

	return entries.NewSearchLogQueryOK().WithPayload(resultPayload)
}

var ErrNotFound = errors.New("grpc returned 0 leaves with success code")

func retrieveLogEntryByIndex(ctx context.Context, logIndex int) (models.LogEntry, error) {
	log.ContextLogger(ctx).Infof("Retrieving log entry by index %d", logIndex)

	tid, resolvedIndex := api.logRanges.ResolveVirtualIndex(logIndex)
	tc := NewTrillianClientFromTreeID(ctx, tid)
	log.ContextLogger(ctx).Debugf("Retrieving resolved index %v from TreeID %v", resolvedIndex, tid)

	resp := tc.getLeafAndProofByIndex(resolvedIndex)
	switch resp.status {
	case codes.OK:
	case codes.NotFound, codes.OutOfRange, codes.InvalidArgument:
		return models.LogEntry{}, ErrNotFound
	default:
		return models.LogEntry{}, fmt.Errorf("grpc err: %w: %s", resp.err, trillianCommunicationError)
	}

	result := resp.getLeafAndProofResult
	leaf := result.Leaf
	if leaf == nil {
		return models.LogEntry{}, ErrNotFound
	}

	return logEntryFromLeaf(ctx, api.signer, tc, leaf, result.SignedLogRoot, result.Proof, tid, api.logRanges)
}

// Retrieve a Log Entry
// If a tree ID is specified, look in that tree
// Otherwise, look through all inactive and active shards
func retrieveLogEntry(ctx context.Context, entryUUID string) (models.LogEntry, error) {
	log.ContextLogger(ctx).Debugf("Retrieving log entry %v", entryUUID)

	uuid, err := sharding.GetUUIDFromIDString(entryUUID)
	if err != nil {
		return nil, sharding.ErrPlainUUID
	}

	// Get the tree ID and check that shard for the entry
	tid, err := sharding.TreeID(entryUUID)
	if err == nil {
		return retrieveUUIDFromTree(ctx, uuid, tid)
	}

	// If we got a UUID instead of an EntryID, search all shards
	if errors.Is(err, sharding.ErrPlainUUID) {
		trees := []sharding.LogRange{{TreeID: api.logRanges.ActiveTreeID()}}
		trees = append(trees, api.logRanges.GetInactive()...)

		for _, t := range trees {
			logEntry, err := retrieveUUIDFromTree(ctx, uuid, t.TreeID)
			if err != nil {
				continue
			}
			return logEntry, nil
		}
		return nil, ErrNotFound
	}

	return nil, err
}

func retrieveUUIDFromTree(ctx context.Context, uuid string, tid int64) (models.LogEntry, error) {
	log.ContextLogger(ctx).Debugf("Retrieving log entry %v from tree %d", uuid, tid)

	hashValue, err := hex.DecodeString(uuid)
	if err != nil {
		return models.LogEntry{}, types.ValidationError(err)
	}

	tc := NewTrillianClientFromTreeID(ctx, tid)
	log.ContextLogger(ctx).Debugf("Attempting to retrieve UUID %v from TreeID %v", uuid, tid)

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
		log.ContextLogger(ctx).Errorf("Unexpected response code while attempting to retrieve UUID %v from TreeID %v: %v", uuid, tid, resp.status)
		return models.LogEntry{}, errors.New("unexpected error")
	}
}

// handlers for APIs that may be disabled in a given instance

func CreateLogEntryNotImplementedHandler(params entries.CreateLogEntryParams) middleware.Responder {
	err := &models.Error{
		Code:    http.StatusNotImplemented,
		Message: "Create Entry API not enabled in this Rekor instance",
	}

	return entries.NewCreateLogEntryDefault(http.StatusNotImplemented).WithPayload(err)
}

func GetLogEntryByIndexNotImplementedHandler(params entries.GetLogEntryByIndexParams) middleware.Responder {
	err := &models.Error{
		Code:    http.StatusNotImplemented,
		Message: "Get Log Entry by Index API not enabled in this Rekor instance",
	}

	return entries.NewGetLogEntryByIndexDefault(http.StatusNotImplemented).WithPayload(err)
}

func GetLogEntryByUUIDNotImplementedHandler(params entries.GetLogEntryByUUIDParams) middleware.Responder {
	err := &models.Error{
		Code:    http.StatusNotImplemented,
		Message: "Get Log Entry by UUID API not enabled in this Rekor instance",
	}

	return entries.NewGetLogEntryByUUIDDefault(http.StatusNotImplemented).WithPayload(err)
}

func SearchLogQueryNotImplementedHandler(params entries.SearchLogQueryParams) middleware.Responder {
	err := &models.Error{
		Code:    http.StatusNotImplemented,
		Message: "Search Log Query API not enabled in this Rekor instance",
	}

	return entries.NewSearchLogQueryDefault(http.StatusNotImplemented).WithPayload(err)
}
