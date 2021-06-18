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
	"net/url"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/google/trillian"
	rfc6962 "github.com/google/trillian/merkle/rfc6962/hasher"
	ttypes "github.com/google/trillian/types"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"
	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/grpc/codes"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/entries"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature"
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
	signature, _, err := signer.Sign(ctx, canonicalized)
	if err != nil {
		return nil, fmt.Errorf("signing error: %v", err)
	}
	return signature, nil
}

// logEntryFromLeaf creates a signed LogEntry struct from trillian structs
func logEntryFromLeaf(ctx context.Context, signer signature.Signer, tc TrillianClient, leaf *trillian.LogLeaf,
	signedLogRoot *trillian.SignedLogRoot, proof *trillian.Proof) (models.LogEntry, error) {

	root := &ttypes.LogRootV1{}
	if err := root.UnmarshalBinary(signedLogRoot.LogRoot); err != nil {
		return nil, err
	}
	hashes := []string{}
	for _, hash := range proof.Hashes {
		hashes = append(hashes, hex.EncodeToString(hash))
	}

	logEntryAnon := models.LogEntryAnon{
		LogID:          swag.String(api.pubkeyHash),
		LogIndex:       &leaf.LeafIndex,
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

	logEntryAnon.Verification = &models.LogEntryAnonVerification{
		InclusionProof:       &inclusionProof,
		SignedEntryTimestamp: strfmt.Base64(signature),
	}

	return models.LogEntry{
		hex.EncodeToString(leaf.MerkleLeafHash): logEntryAnon}, nil
}

// GetLogEntryAndProofByIndexHandler returns the entry and inclusion proof for a specified log index
func GetLogEntryByIndexHandler(params entries.GetLogEntryByIndexParams) middleware.Responder {
	ctx := params.HTTPRequest.Context()
	tc := NewTrillianClient(ctx)

	resp := tc.getLeafAndProofByIndex(params.LogIndex)
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

	logEntry, err := logEntryFromLeaf(ctx, api.signer, tc, leaf, result.SignedLogRoot, result.Proof)
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, err, err.Error())
	}

	return entries.NewGetLogEntryByIndexOK().WithPayload(logEntry)
}

func createLogEntry(ctx context.Context, params entries.CreateLogEntryParams) (models.LogEntry, middleware.Responder) {
	entry, err := types.NewEntry(params.ProposedEntry)
	if err != nil {
		return nil, handleRekorAPIError(params, http.StatusBadRequest, err, err.Error())
	}
	leaf, err := entry.Canonicalize(ctx)
	if err != nil {
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

	logEntryAnon := models.LogEntryAnon{
		LogID:          swag.String(api.pubkeyHash),
		LogIndex:       swag.Int64(queuedLeaf.LeafIndex),
		Body:           queuedLeaf.GetLeafValue(),
		IntegratedTime: swag.Int64(queuedLeaf.IntegrateTimestamp.AsTime().Unix()),
	}

	if viper.GetBool("enable_retrieve_api") {
		go func() {
			for _, key := range entry.IndexKeys() {
				if err := addToIndex(context.Background(), key, uuid); err != nil {
					log.RequestIDLogger(params.HTTPRequest).Error(err)
				}
			}
		}()
	}

	if viper.GetBool("enable_attestation_storage") {

		go func() {
			typ, attestation := entry.Attestation()
			if typ == "" {
				log.RequestIDLogger(params.HTTPRequest).Infof("no attestation for %s", uuid)
				return
			}
			if err := storeAttestation(context.Background(), uuid, typ, attestation); err != nil {
				log.RequestIDLogger(params.HTTPRequest).Errorf("error storing attestation: %s", err)
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
	ctx := params.HTTPRequest.Context()
	httpReq := params.HTTPRequest

	logEntry, err := createLogEntry(ctx, params)
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
	ctx := params.HTTPRequest.Context()
	hashValue, _ := hex.DecodeString(params.EntryUUID)
	tc := NewTrillianClient(params.HTTPRequest.Context())

	resp := tc.getLeafAndProofByHash(hashValue)
	switch resp.status {
	case codes.OK:
	case codes.NotFound:
		return handleRekorAPIError(params, http.StatusNotFound, fmt.Errorf("grpc error: %w", resp.err), "")
	default:
		return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("grpc error: %w", resp.err), trillianUnexpectedResult)
	}

	result := resp.getLeafAndProofResult
	leaf := result.Leaf
	if leaf == nil {
		return handleRekorAPIError(params, http.StatusNotFound, errors.New("grpc returned 0 leaves with success code"), "")
	}

	logEntry, err := logEntryFromLeaf(ctx, api.signer, tc, leaf, result.SignedLogRoot, result.Proof)
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, err, "")
	}

	return entries.NewGetLogEntryByUUIDOK().WithPayload(logEntry)
}

// SearchLogQueryHandler searches log by index, UUID, or proposed entry and returns array of entries found with inclusion proofs
func SearchLogQueryHandler(params entries.SearchLogQueryParams) middleware.Responder {
	httpReqCtx := params.HTTPRequest.Context()
	resultPayload := []models.LogEntry{}
	tc := NewTrillianClient(httpReqCtx)

	if len(params.Entry.EntryUUIDs) > 0 || len(params.Entry.Entries()) > 0 {
		g, _ := errgroup.WithContext(httpReqCtx)

		searchHashes := make([][]byte, len(params.Entry.EntryUUIDs)+len(params.Entry.Entries()))
		for i, uuid := range params.Entry.EntryUUIDs {
			hash, err := hex.DecodeString(uuid)
			if err != nil {
				return handleRekorAPIError(params, http.StatusBadRequest, err, malformedUUID)
			}
			searchHashes[i] = hash
		}

		code := http.StatusBadRequest
		for i, e := range params.Entry.Entries() {
			i, e := i, e // https://golang.org/doc/faq#closures_and_goroutines
			g.Go(func() error {
				entry, err := types.NewEntry(e)
				if err != nil {
					return err
				}
				if err := entry.Validate(); err != nil {
					return err
				}

				if entry.HasExternalEntities() {
					if err := entry.FetchExternalEntities(httpReqCtx); err != nil {
						return err
					}
				}

				leaf, err := entry.Canonicalize(httpReqCtx)
				if err != nil {
					code = http.StatusInternalServerError
					return err
				}
				hasher := rfc6962.DefaultHasher
				leafHash := hasher.HashLeaf(leaf)
				searchHashes[i+len(params.Entry.EntryUUIDs)] = leafHash
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
				logEntry, err := logEntryFromLeaf(httpReqCtx, api.signer, tc, leafResp.Leaf, leafResp.SignedLogRoot, leafResp.Proof)
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
				resp := tc.getLeafAndProofByIndex(swag.Int64Value(logIndex))
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
				logEntry, err := logEntryFromLeaf(httpReqCtx, api.signer, tc, result.Leaf, result.SignedLogRoot, result.Proof)
				if err != nil {
					return handleRekorAPIError(params, http.StatusInternalServerError, err, trillianUnexpectedResult)
				}
				resultPayload = append(resultPayload, logEntry)
			}
		}
	}

	return entries.NewSearchLogQueryOK().WithPayload(resultPayload)
}
