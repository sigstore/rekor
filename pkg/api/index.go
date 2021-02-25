/*
Copyright © 2021 Bob Callaway <bcallawa@redhat.com>

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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"github.com/SigStore/rekor/pkg/pki"

	radix "github.com/mediocregopher/radix/v4"

	"github.com/asaskevich/govalidator"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"
	"github.com/SigStore/rekor/pkg/generated/models"
	"github.com/SigStore/rekor/pkg/generated/restapi/operations/index"
	"github.com/SigStore/rekor/pkg/util"
)

func SearchIndexHandler(params index.SearchIndexParams) middleware.Responder {
	httpReqCtx := params.HTTPRequest.Context()

	var result []string
	if params.Query.Hash != "" {
		//validate this is only a valid sha256 hash
		if !govalidator.IsSHA256(params.Query.Hash) {
			return handleRekorAPIError(params, http.StatusBadRequest, errors.New("invalid hash value specified"), malformedHash)
		}
		var resultUUIDs []string
		if err := redisClient.Do(httpReqCtx, radix.Cmd(&resultUUIDs, "LRANGE", strings.ToLower(params.Query.Hash), "0", "-1")); err != nil {
			return handleRekorAPIError(params, http.StatusInternalServerError, err, redisUnexpectedResult)
		}
		result = append(result, resultUUIDs...)
	}
	if params.Query.PublicKey != nil {
		af := pki.NewArtifactFactory(swag.StringValue(params.Query.PublicKey.Format))
		keyReader, err := util.FileOrURLReadCloser(httpReqCtx, params.Query.PublicKey.URL.String(), params.Query.PublicKey.Content, true)
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

		hasher := sha256.New()
		if _, err := hasher.Write(canonicalKey); err != nil {
			return handleRekorAPIError(params, http.StatusInternalServerError, err, failedToGenerateCanonicalKey)
		}
		keyHash := hasher.Sum(nil)
		var resultUUIDs []string
		if err := redisClient.Do(httpReqCtx, radix.Cmd(&resultUUIDs, "LRANGE", strings.ToLower(hex.EncodeToString(keyHash)), "0", "-1")); err != nil {
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
