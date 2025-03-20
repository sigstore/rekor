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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/google/trillian"
	ttypes "github.com/google/trillian/types"
	"github.com/spf13/viper"
	"github.com/transparency-dev/merkle/rfc6962"
	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/grpc/codes"

	"github.com/sigstore/rekor/pkg/events"
	"github.com/sigstore/rekor/pkg/events/newentry"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/entries"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pki/identity"
	"github.com/sigstore/rekor/pkg/pubsub"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/tle"
	"github.com/sigstore/rekor/pkg/trillianclient"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
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
		return nil, fmt.Errorf("marshalling error: %w", err)
	}
	canonicalized, err := jsoncanonicalizer.Transform(payload)
	if err != nil {
		return nil, fmt.Errorf("canonicalizing error: %w", err)
	}
	signature, err := signer.SignMessage(bytes.NewReader(canonicalized), options.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("signing error: %w", err)
	}
	return signature, nil
}

// logEntryFromLeaf creates a signed LogEntry struct from trillian structs
func logEntryFromLeaf(ctx context.Context, leaf *trillian.LogLeaf, signedLogRoot *trillian.SignedLogRoot,
	proof *trillian.Proof, tid int64, ranges sharding.LogRanges, cachedCheckpoints map[int64]string) (models.LogEntry, error) {

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
	logRange, err := ranges.GetLogRangeByTreeID(tid)
	if err != nil {
		return nil, err
	}

	logEntryAnon := models.LogEntryAnon{
		LogID:          swag.String(logRange.LogID),
		LogIndex:       &virtualIndex,
		Body:           leaf.LeafValue,
		IntegratedTime: swag.Int64(leaf.IntegrateTimestamp.AsTime().Unix()),
	}

	signature, err := signEntry(ctx, logRange.Signer, logEntryAnon)
	if err != nil {
		return nil, fmt.Errorf("signing entry error: %w", err)
	}

	// If tree ID is inactive, use cached checkpoint
	var sc string
	val, ok := cachedCheckpoints[tid]
	if ok {
		sc = val
	} else {
		scBytes, err := util.CreateAndSignCheckpoint(ctx, viper.GetString("rekor_server.hostname"), tid, root.TreeSize, root.RootHash, logRange.Signer)
		if err != nil {
			return nil, err
		}
		sc = string(scBytes)
	}

	inclusionProof := models.InclusionProof{
		TreeSize:   swag.Int64(int64(root.TreeSize)),
		RootHash:   swag.String(hex.EncodeToString(root.RootHash)),
		LogIndex:   swag.Int64(proof.GetLeafIndex()),
		Hashes:     hashes,
		Checkpoint: stringPointer(sc),
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
				att, fetchErr = attestationStorageClient.FetchAttestation(ctx, attKey)
				if fetchErr != nil {
					log.ContextLogger(ctx).Debugf("error fetching attestation by key, trying by UUID: %s %v", attKey, fetchErr)
				}
			}
			// if looking up by key failed or we weren't able to generate a key, try looking up by uuid
			if attKey == "" || fetchErr != nil {
				att, fetchErr = attestationStorageClient.FetchAttestation(ctx, entryIDstruct.UUID)
				if fetchErr != nil {
					log.ContextLogger(ctx).Debugf("error fetching attestation by uuid: %s %v", entryIDstruct.UUID, fetchErr)
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

// GetLogEntryByIndexHandler returns the entry and inclusion proof for a specified log index
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

func getArtifactHashValue(entry types.EntryImpl) crypto.Hash {
	artifactHash, err := entry.ArtifactHash()
	if err != nil {
		// Default to SHA256 if no artifact hash is specified
		return crypto.SHA256
	}

	var artifactHashAlgorithm string
	algoPosition := strings.Index(artifactHash, ":")
	if algoPosition != -1 {
		artifactHashAlgorithm = artifactHash[:algoPosition]
	}
	switch artifactHashAlgorithm {
	case "sha256":
		return crypto.SHA256
	case "sha384":
		return crypto.SHA384
	case "sha512":
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

func getPublicKey(identity identity.Identity) (crypto.PublicKey, error) {
	switch identityCrypto := identity.Crypto.(type) {
	case *x509.Certificate:
		return identityCrypto.PublicKey, nil
	case *rsa.PublicKey:
		return identityCrypto, nil
	case *ecdsa.PublicKey:
		return identityCrypto, nil
	case ed25519.PublicKey:
		return identityCrypto, nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", identityCrypto)
	}
}

func checkEntryAlgorithms(entry types.EntryImpl) (bool, error) {
	// Only check algorithms for hashedrekord entries
	switch entry.(type) {
	case *hashedrekord.V001Entry:
		break
	default:
		return true, nil
	}

	verifiers, err := entry.Verifiers()
	if err != nil {
		return false, err
	}

	artifactHashValue := getArtifactHashValue(entry)

	// Check if all the verifiers public keys (together with the
	// artifactHashValue) are allowed according to the policy
	for _, v := range verifiers {
		identities, err := v.Identities()
		if err != nil {
			return false, err
		}

		for _, identity := range identities {
			publicKey, err := getPublicKey(identity)
			if err != nil {
				return false, err
			}
			isPermitted, err := api.algorithmRegistry.IsAlgorithmPermitted(publicKey, artifactHashValue)
			if err != nil {
				return false, fmt.Errorf("checking if algorithm is permitted: %w", err)
			}
			if !isPermitted {
				return false, nil
			}
		}
	}
	return true, nil
}

func createLogEntry(params entries.CreateLogEntryParams) (models.LogEntry, middleware.Responder) {
	ctx := params.HTTPRequest.Context()
	entry, err := types.CreateVersionedEntry(params.ProposedEntry)
	if err != nil {
		return nil, handleRekorAPIError(params, http.StatusBadRequest, err, fmt.Sprintf(validationError, err))
	}

	areEntryAlgorithmsAllowed, err := checkEntryAlgorithms(entry)
	if err != nil {
		return nil, handleRekorAPIError(params, http.StatusBadRequest, err, fmt.Sprintf(validationError, err))
	}
	if !areEntryAlgorithmsAllowed {
		return nil, handleRekorAPIError(params, http.StatusBadRequest, errors.New("entry algorithms are not allowed"), fmt.Sprintf(validationError, "entry algorithms are not allowed"))
	}

	leaf, err := types.CanonicalizeEntry(ctx, entry)
	if err != nil {
		var validationErr *types.InputValidationError
		if errors.As(err, &validationErr) {
			return nil, handleRekorAPIError(params, http.StatusBadRequest, err, fmt.Sprintf(validationError, err))
		}
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, err, failedToGenerateCanonicalEntry)
	}

	tc := trillianclient.NewTrillianClient(ctx, api.logClient, api.treeID)

	resp := tc.AddLeaf(leaf)
	// this represents overall GRPC response state (not the results of insertion into the log)
	if resp.Status != codes.OK {
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("grpc error: %w", resp.Err), trillianUnexpectedResult)
	}

	// this represents the results of inserting the proposed leaf into the log; status is nil in success path
	insertionStatus := resp.GetAddResult.QueuedLeaf.Status
	if insertionStatus != nil {
		switch insertionStatus.Code {
		case int32(code.Code_OK):
		case int32(code.Code_ALREADY_EXISTS), int32(code.Code_FAILED_PRECONDITION):
			existingUUID := hex.EncodeToString(rfc6962.DefaultHasher.HashLeaf(leaf))
			activeTree := fmt.Sprintf("%x", api.treeID)
			entryIDstruct, err := sharding.CreateEntryIDFromParts(activeTree, existingUUID)
			if err != nil {
				err := fmt.Errorf("error creating EntryID from active treeID %v and uuid %v: %w", activeTree, existingUUID, err)
				return nil, handleRekorAPIError(params, http.StatusInternalServerError, err, fmt.Sprintf(validationError, err))
			}
			existingEntryID := entryIDstruct.ReturnEntryIDString()
			err = fmt.Errorf("grpc error: %v", insertionStatus.String())
			return nil, handleRekorAPIError(params, http.StatusConflict, err, fmt.Sprintf(entryAlreadyExists, existingEntryID), "entryURL", getEntryURL(*params.HTTPRequest.URL, existingEntryID))
		default:
			err := fmt.Errorf("grpc error: %v", insertionStatus.String())
			return nil, handleRekorAPIError(params, http.StatusInternalServerError, err, trillianUnexpectedResult)
		}
	}

	// We made it this far, that means the entry was successfully added.
	metricNewEntries.Inc()

	queuedLeaf := resp.GetAddResult.QueuedLeaf.Leaf

	uuid := hex.EncodeToString(queuedLeaf.GetMerkleLeafHash())
	activeTree := fmt.Sprintf("%x", api.treeID)
	entryIDstruct, err := sharding.CreateEntryIDFromParts(activeTree, uuid)
	if err != nil {
		err := fmt.Errorf("error creating EntryID from active treeID %v and uuid %v: %w", activeTree, uuid, err)
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, err, fmt.Sprintf(validationError, err))
	}
	entryID := entryIDstruct.ReturnEntryIDString()

	// The log index should be the virtual log index across all shards
	virtualIndex := sharding.VirtualLogIndex(queuedLeaf.LeafIndex, api.logRanges.GetActive().TreeID, api.logRanges)
	logEntryAnon := models.LogEntryAnon{
		LogID:          swag.String(api.logRanges.GetActive().LogID),
		LogIndex:       swag.Int64(virtualIndex),
		Body:           queuedLeaf.GetLeafValue(),
		IntegratedTime: swag.Int64(queuedLeaf.IntegrateTimestamp.AsTime().Unix()),
	}

	if indexStorageClient != nil {
		go func() {
			start := time.Now()
			var err error
			defer func() {
				labels := map[string]string{
					"success": strconv.FormatBool(err == nil),
				}
				metricIndexStorageLatency.With(labels).Observe(float64(time.Since(start)))
			}()
			keys, err := entry.IndexKeys()
			if err != nil {
				log.ContextLogger(ctx).Errorf("getting entry index keys: %v", err)
				return
			}
			if err := addToIndex(context.Background(), keys, entryID); err != nil {
				log.ContextLogger(ctx).Errorf("adding keys to index: %v", err)
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
						log.ContextLogger(ctx).Debugf("error storing attestation: %s", err)
					} else {
						log.ContextLogger(ctx).Debugf("stored attestation for uuid %s with filename %s", entryIDstruct.UUID, attKey)
					}
				}()
			} else {
				log.ContextLogger(ctx).Infof("no attestation returned for %s", uuid)
			}
		}
	}

	signature, err := signEntry(ctx, api.logRanges.GetActive().Signer, logEntryAnon)
	if err != nil {
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("signing entry error: %w", err), signingError)
	}

	root := &ttypes.LogRootV1{}
	if err := root.UnmarshalBinary(resp.GetLeafAndProofResult.SignedLogRoot.LogRoot); err != nil {
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("error unmarshalling log root: %w", err), sthGenerateError)
	}
	hashes := []string{}
	for _, hash := range resp.GetLeafAndProofResult.Proof.Hashes {
		hashes = append(hashes, hex.EncodeToString(hash))
	}

	scBytes, err := util.CreateAndSignCheckpoint(ctx, viper.GetString("rekor_server.hostname"), api.treeID, root.TreeSize, root.RootHash, api.logRanges.GetActive().Signer)
	if err != nil {
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, err, sthGenerateError)
	}

	inclusionProof := models.InclusionProof{
		TreeSize:   swag.Int64(int64(root.TreeSize)),
		RootHash:   swag.String(hex.EncodeToString(root.RootHash)),
		LogIndex:   swag.Int64(queuedLeaf.LeafIndex),
		Hashes:     hashes,
		Checkpoint: swag.String(string(scBytes)),
	}

	logEntryAnon.Verification = &models.LogEntryAnonVerification{
		InclusionProof:       &inclusionProof,
		SignedEntryTimestamp: strfmt.Base64(signature),
	}

	logEntry := models.LogEntry{
		entryID: logEntryAnon,
	}

	if api.newEntryPublisher != nil {
		// Publishing notifications should not block the API response.
		go func() {
			verifiers, err := entry.Verifiers()
			if err != nil {
				incPublishEvent(newentry.Name, "", false)
				log.ContextLogger(ctx).Errorf("Could not get verifiers for log entry %s: %v", entryID, err)
				return
			}
			var subjects []string
			for _, v := range verifiers {
				subjects = append(subjects, v.Subjects()...)
			}

			pbEntry, err := tle.GenerateTransparencyLogEntry(logEntryAnon)
			if err != nil {
				incPublishEvent(newentry.Name, "", false)
				log.ContextLogger(ctx).Error(err)
				return
			}
			event, err := newentry.New(entryID, pbEntry, subjects)
			if err != nil {
				incPublishEvent(newentry.Name, "", false)
				log.ContextLogger(ctx).Error(err)
				return
			}
			if viper.GetBool("rekor_server.publish_events_protobuf") {
				go publishEvent(ctx, api.newEntryPublisher, event, events.ContentTypeProtobuf)
			}
			if viper.GetBool("rekor_server.publish_events_json") {
				go publishEvent(ctx, api.newEntryPublisher, event, events.ContentTypeJSON)
			}
		}()
	}

	return logEntry, nil
}

func publishEvent(ctx context.Context, publisher pubsub.Publisher, event *events.Event, contentType events.EventContentType) {
	err := publisher.Publish(context.WithoutCancel(ctx), event, contentType)
	incPublishEvent(event.Type().Name(), contentType, err == nil)
	if err != nil {
		log.ContextLogger(ctx).Error(err)
	}
}

func incPublishEvent(event string, contentType events.EventContentType, ok bool) {
	status := "SUCCESS"
	if !ok {
		status = "ERROR"
	}
	labels := map[string]string{
		"event":        event,
		"status":       status,
		"content_type": string(contentType),
	}
	metricPublishEvents.With(labels).Inc()
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
		var validationErr *types.InputValidationError
		if errors.As(err, &validationErr) {
			return handleRekorAPIError(params, http.StatusBadRequest, err, fmt.Sprintf("validation error: %v", err))
		}
		return handleRekorAPIError(params, http.StatusInternalServerError, err, trillianCommunicationError)
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
		for _, e := range entries {
			entry, err := types.UnmarshalEntry(e)
			if err != nil {
				return handleRekorAPIError(params, http.StatusBadRequest, fmt.Errorf("unmarshalling entry: %w", err), err.Error())
			}

			leaf, err := types.CanonicalizeEntry(httpReqCtx, entry)
			if err != nil {
				return handleRekorAPIError(params, http.StatusBadRequest, fmt.Errorf("canonicalizing entry: %w", err), err.Error())
			}
			hasher := rfc6962.DefaultHasher
			leafHash := hasher.HashLeaf(leaf)
			searchHashes = append(searchHashes, leafHash)
		}

		searchByHashResults := make([]map[int64]*trillian.GetEntryAndProofResponse, len(searchHashes))
		for i, hash := range searchHashes {
			var results map[int64]*trillian.GetEntryAndProofResponse
			for _, shard := range api.logRanges.AllShards() {
				tcs := trillianclient.NewTrillianClient(httpReqCtx, api.logClient, shard)
				resp := tcs.GetLeafAndProofByHash(hash)
				switch resp.Status {
				case codes.OK:
					leafResult := resp.GetLeafAndProofResult
					if leafResult != nil && leafResult.Leaf != nil {
						if results == nil {
							results = map[int64]*trillian.GetEntryAndProofResponse{}
						}
						results[shard] = resp.GetLeafAndProofResult
					}
				case codes.NotFound:
					// do nothing here, do not throw 404 error
					continue
				default:
					return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("error getLeafAndProofByHash(%s): code: %v, msg %v", hex.EncodeToString(hash), resp.Status, resp.Err), trillianCommunicationError)
				}
			}
			searchByHashResults[i] = results
		}

		for _, hashMap := range searchByHashResults {
			for shard, leafResp := range hashMap {
				if leafResp == nil {
					continue
				}
				logEntry, err := logEntryFromLeaf(httpReqCtx, leafResp.Leaf, leafResp.SignedLogRoot, leafResp.Proof, shard, api.logRanges, api.cachedCheckpoints)
				if err != nil {
					return handleRekorAPIError(params, http.StatusInternalServerError, err, err.Error())
				}
				resultPayload = append(resultPayload, logEntry)
			}
		}
	}

	if len(params.Entry.LogIndexes) > 0 {
		for _, logIndex := range params.Entry.LogIndexes {
			logEntry, err := retrieveLogEntryByIndex(httpReqCtx, int(swag.Int64Value(logIndex)))
			if err != nil && !errors.Is(err, ErrNotFound) {
				return handleRekorAPIError(params, http.StatusInternalServerError, err, err.Error())
			} else if err == nil {
				resultPayload = append(resultPayload, logEntry)
			}
		}
	}

	return entries.NewSearchLogQueryOK().WithPayload(resultPayload)
}

var ErrNotFound = errors.New("grpc returned 0 leaves with success code")

func retrieveLogEntryByIndex(ctx context.Context, logIndex int) (models.LogEntry, error) {
	log.ContextLogger(ctx).Infof("Retrieving log entry by index %d", logIndex)

	tid, resolvedIndex := api.logRanges.ResolveVirtualIndex(logIndex)
	tc := trillianclient.NewTrillianClient(ctx, api.logClient, tid)
	log.ContextLogger(ctx).Debugf("Retrieving resolved index %v from TreeID %v", resolvedIndex, tid)

	resp := tc.GetLeafAndProofByIndex(resolvedIndex)
	switch resp.Status {
	case codes.OK:
	case codes.NotFound, codes.OutOfRange, codes.InvalidArgument:
		return models.LogEntry{}, ErrNotFound
	default:
		return models.LogEntry{}, fmt.Errorf("grpc err: %w: %s", resp.Err, trillianCommunicationError)
	}

	result := resp.GetLeafAndProofResult
	leaf := result.Leaf
	if leaf == nil {
		return models.LogEntry{}, ErrNotFound
	}

	return logEntryFromLeaf(ctx, leaf, result.SignedLogRoot, result.Proof, tid, api.logRanges, api.cachedCheckpoints)
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
		trees := []sharding.LogRange{api.logRanges.GetActive()}
		trees = append(trees, api.logRanges.GetInactive()...)

		for _, t := range trees {
			logEntry, err := retrieveUUIDFromTree(ctx, uuid, t.TreeID)
			if err != nil {
				if errors.Is(err, ErrNotFound) {
					continue
				}
				return nil, err
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
		return models.LogEntry{}, &types.InputValidationError{Err: fmt.Errorf("parsing UUID: %w", err)}
	}

	tc := trillianclient.NewTrillianClient(ctx, api.logClient, tid)
	log.ContextLogger(ctx).Debugf("Attempting to retrieve UUID %v from TreeID %v", uuid, tid)

	resp := tc.GetLeafAndProofByHash(hashValue)
	switch resp.Status {
	case codes.OK:
		result := resp.GetLeafAndProofResult
		if resp.Err != nil {
			// this shouldn't be possible since GetLeafAndProofByHash verifies the inclusion proof using a computed leaf hash
			// so this is just a defensive check
			if result.Leaf == nil {
				return models.LogEntry{}, ErrNotFound
			}
			return models.LogEntry{}, err
		}

		logEntry, err := logEntryFromLeaf(ctx, result.Leaf, result.SignedLogRoot, result.Proof, tid, api.logRanges, api.cachedCheckpoints)
		if err != nil {
			return models.LogEntry{}, fmt.Errorf("could not create log entry from leaf: %w", err)
		}
		return logEntry, nil

	case codes.NotFound:
		return models.LogEntry{}, ErrNotFound
	default:
		log.ContextLogger(ctx).Errorf("Unexpected response code while attempting to retrieve UUID %v from TreeID %v: %v", uuid, tid, resp.Status)
		return models.LogEntry{}, errors.New("unexpected error")
	}
}

// handlers for APIs that may be disabled in a given instance

func CreateLogEntryNotImplementedHandler(_ entries.CreateLogEntryParams) middleware.Responder {
	err := &models.Error{
		Code:    http.StatusNotImplemented,
		Message: "Create Entry API not enabled in this Rekor instance",
	}

	return entries.NewCreateLogEntryDefault(http.StatusNotImplemented).WithPayload(err)
}

func GetLogEntryByIndexNotImplementedHandler(_ entries.GetLogEntryByIndexParams) middleware.Responder {
	err := &models.Error{
		Code:    http.StatusNotImplemented,
		Message: "Get Log Entry by Index API not enabled in this Rekor instance",
	}

	return entries.NewGetLogEntryByIndexDefault(http.StatusNotImplemented).WithPayload(err)
}

func GetLogEntryByUUIDNotImplementedHandler(_ entries.GetLogEntryByUUIDParams) middleware.Responder {
	err := &models.Error{
		Code:    http.StatusNotImplemented,
		Message: "Get Log Entry by UUID API not enabled in this Rekor instance",
	}

	return entries.NewGetLogEntryByUUIDDefault(http.StatusNotImplemented).WithPayload(err)
}

func SearchLogQueryNotImplementedHandler(_ entries.SearchLogQueryParams) middleware.Responder {
	err := &models.Error{
		Code:    http.StatusNotImplemented,
		Message: "Search Log Query API not enabled in this Rekor instance",
	}

	return entries.NewSearchLogQueryDefault(http.StatusNotImplemented).WithPayload(err)
}
