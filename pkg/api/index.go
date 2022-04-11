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
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"
	radix "github.com/mediocregopher/radix/v4"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/index"
	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/util"
)

func SearchIndexHandler(params index.SearchIndexParams) middleware.Responder {
	httpReqCtx := params.HTTPRequest.Context()

	var result []string
	if params.Query.Hash != "" {
		// This must be a valid sha256 hash
		sha := util.PrefixSHA(params.Query.Hash)
		var resultUUIDs []string
		if err := redisClient.Do(httpReqCtx, radix.Cmd(&resultUUIDs, "LRANGE", strings.ToLower(sha), "0", "-1")); err != nil {
			return handleRekorAPIError(params, http.StatusInternalServerError, err, redisUnexpectedResult)
		}
		result = append(result, resultUUIDs...)
	}
	if params.Query.PublicKey != nil {
		af, err := pki.NewArtifactFactory(pki.Format(swag.StringValue(params.Query.PublicKey.Format)))
		if err != nil {
			return handleRekorAPIError(params, http.StatusBadRequest, err, unsupportedPKIFormat)
		}
		keyReader, err := util.FileOrURLReadCloser(httpReqCtx, params.Query.PublicKey.URL.String(), params.Query.PublicKey.Content)
		if err != nil {
			return handleRekorAPIError(params, http.StatusBadRequest, err, malformedPublicKey)
		}
		defer keyReader.Close()

		key, err := af.NewPublicKey(keyReader)
		if err != nil {
			return handleRekorAPIError(params, http.StatusBadRequest, err, malformedPublicKey)
		}
		canonicalKey, err := key.CanonicalValue()
		if err != nil {
			return handleRekorAPIError(params, http.StatusInternalServerError, err, failedToGenerateCanonicalKey)
		}

		keyHash := sha256.Sum256(canonicalKey)
		var resultUUIDs []string
		if err := redisClient.Do(httpReqCtx, radix.Cmd(&resultUUIDs, "LRANGE", strings.ToLower(hex.EncodeToString(keyHash[:])), "0", "-1")); err != nil {
			return handleRekorAPIError(params, http.StatusInternalServerError, err, redisUnexpectedResult)
		}
		result = append(result, resultUUIDs...)
	}
	if params.Query.Email != "" {
		var resultUUIDs []string
		if err := redisClient.Do(httpReqCtx, radix.Cmd(&resultUUIDs, "LRANGE", strings.ToLower(params.Query.Email.String()), "0", "-1")); err != nil {
			return handleRekorAPIError(params, http.StatusInternalServerError, err, redisUnexpectedResult)
		}
		result = append(result, resultUUIDs...)
	}

	return index.NewSearchIndexOK().WithPayload(result)
}

func SearchIndexNotImplementedHandler(params index.SearchIndexParams) middleware.Responder {
	err := models.Error{
		Code:    http.StatusNotImplemented,
		Message: "Search Index API not enabled in this Rekor instance",
	}

	return index.NewSearchIndexDefault(http.StatusNotImplemented).WithPayload(&err)

}

func addToIndex(ctx context.Context, key, value string) error {
	return redisClient.Do(ctx, radix.Cmd(nil, "LPUSH", key, value))
}

func storeAttestation(ctx context.Context, uuid string, attestation []byte) error {
	return storageClient.StoreAttestation(ctx, uuid, attestation)
}
