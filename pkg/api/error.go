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
	"fmt"
	"net/http"
	"regexp"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/mitchellh/mapstructure"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/entries"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/index"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/pubkey"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/tlog"
	"github.com/sigstore/rekor/pkg/log"
)

const (
	trillianCommunicationError     = "unexpected error communicating with transparency log"
	trillianUnexpectedResult       = "unexpected result from transparency log"
	validationError                = "error processing entry: %v"
	failedToGenerateCanonicalEntry = "error generating canonicalized entry"
	entryAlreadyExists             = "an equivalent entry already exists in the transparency log with UUID %v"
	firstSizeLessThanLastSize      = "firstSize(%d) must be less than lastSize(%d)"
	malformedUUID                  = "UUID must be a 64-character hexadecimal string"
	malformedPublicKey             = "public key provided could not be parsed"
	failedToGenerateCanonicalKey   = "error generating canonicalized public key"
	redisUnexpectedResult          = "unexpected result from searching index"
	lastSizeGreaterThanKnown       = "the tree size requested(%d) was greater than what is currently observable(%d)"
	signingError                   = "error signing"
	sthGenerateError               = "error generating signed tree head"
	unsupportedPKIFormat           = "the PKI format requested is not supported by this server"
	unexpectedInactiveShardError   = "unexpected error communicating with inactive shard"
	maxSearchQueryLimit            = "more than max allowed %d entries in request"
)

func errorMsg(message string, code int) *models.Error {
	return &models.Error{
		Code:    int64(code),
		Message: message,
	}
}

func handleRekorAPIError(params interface{}, code int, err error, message string, fields ...interface{}) middleware.Responder {
	if message == "" {
		message = http.StatusText(code)
	}

	re := regexp.MustCompile("^(.*)Params$")
	typeStr := fmt.Sprintf("%T", params)
	handler := re.FindStringSubmatch(typeStr)[1]

	logMsg := func(r *http.Request) {
		ctx := r.Context()
		fields := append([]interface{}{"handler", handler, "statusCode", code, "clientMessage", message}, fields...)
		if code >= 500 {
			log.ContextLogger(ctx).Errorw(err.Error(), fields...)
		} else {
			log.ContextLogger(ctx).Warnw(err.Error(), fields...)
		}
		paramsFields := map[string]interface{}{}
		if err := mapstructure.Decode(params, &paramsFields); err == nil {
			log.ContextLogger(ctx).Debug(paramsFields)
		}
	}

	switch params := params.(type) {
	case entries.GetLogEntryByIndexParams:
		logMsg(params.HTTPRequest)
		switch code {
		case http.StatusNotFound:
			return entries.NewGetLogEntryByIndexNotFound()
		default:
			return entries.NewGetLogEntryByIndexDefault(code).WithPayload(errorMsg(message, code))
		}
	case entries.GetLogEntryByUUIDParams:
		logMsg(params.HTTPRequest)
		switch code {
		case http.StatusNotFound:
			return entries.NewGetLogEntryByUUIDNotFound()
		default:
			return entries.NewGetLogEntryByUUIDDefault(code).WithPayload(errorMsg(message, code))
		}
	case entries.CreateLogEntryParams:
		switch code {
		// We treat "duplicate entry" as an error, but it's not really an error, so we don't need to log it as one.
		case http.StatusBadRequest:
			logMsg(params.HTTPRequest)
			return entries.NewCreateLogEntryBadRequest().WithPayload(errorMsg(message, code))
		case http.StatusConflict:
			resp := entries.NewCreateLogEntryConflict().WithPayload(errorMsg(message, code))
			locationFound := false
			for _, field := range fields {
				if locationFound {
					existingURL := field.(strfmt.URI)
					resp.SetLocation(existingURL)
					break
				} else if field.(string) == "entryURL" {
					locationFound = true
					continue
				}
			}
			return resp
		default:
			logMsg(params.HTTPRequest)
			return entries.NewCreateLogEntryDefault(code).WithPayload(errorMsg(message, code))
		}
	case entries.SearchLogQueryParams:
		logMsg(params.HTTPRequest)
		switch code {
		case http.StatusBadRequest:
			return entries.NewSearchLogQueryBadRequest().WithPayload(errorMsg(message, code))
		case http.StatusUnprocessableEntity:
			return entries.NewSearchLogQueryUnprocessableEntity().WithPayload(errorMsg(message, code))
		default:
			return entries.NewSearchLogQueryDefault(code).WithPayload(errorMsg(message, code))
		}
	case tlog.GetLogInfoParams:
		logMsg(params.HTTPRequest)
		return tlog.NewGetLogInfoDefault(code).WithPayload(errorMsg(message, code))
	case tlog.GetLogProofParams:
		logMsg(params.HTTPRequest)
		switch code {
		case http.StatusBadRequest:
			return tlog.NewGetLogProofBadRequest().WithPayload(errorMsg(message, code))
		default:
			return tlog.NewGetLogProofDefault(code).WithPayload(errorMsg(message, code))
		}
	case pubkey.GetPublicKeyParams:
		logMsg(params.HTTPRequest)
		return pubkey.NewGetPublicKeyDefault(code).WithPayload(errorMsg(message, code))
	case index.SearchIndexParams:
		logMsg(params.HTTPRequest)
		switch code {
		case http.StatusBadRequest:
			return index.NewSearchIndexBadRequest().WithPayload(errorMsg(message, code))
		default:
			return index.NewSearchIndexDefault(code).WithPayload(errorMsg(message, code))
		}
	default:
		log.Logger.Errorf("unable to find method for type %T; error: %v", params, err)
		return middleware.Error(http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
	}
}
