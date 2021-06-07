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
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/timestamp"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/tlog"
	"github.com/sigstore/rekor/pkg/log"
)

const (
	trillianCommunicationError        = "Unexpected error communicating with transparency log"
	trillianUnexpectedResult          = "Unexpected result from transparency log"
	failedToGenerateCanonicalEntry    = "Error generating canonicalized entry"
	entryAlreadyExists                = "An equivalent entry already exists in the transparency log with UUID %v"
	firstSizeLessThanLastSize         = "firstSize(%d) must be less than lastSize(%d)"
	malformedUUID                     = "UUID must be a 64-character hexadecimal string"
	malformedPublicKey                = "Public key provided could not be parsed"
	failedToGenerateCanonicalKey      = "Error generating canonicalized public key"
	redisUnexpectedResult             = "Unexpected result from searching index"
	lastSizeGreaterThanKnown          = "The tree size requested(%d) was greater than what is currently observable(%d)"
	signingError                      = "Error signing"
	failedToGenerateTimestampResponse = "Error generating timestamp response"
	sthGenerateError                  = "Error generating signed tree head"
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
		log.RequestIDLogger(r).Errorw("exiting with error", append([]interface{}{"handler", handler, "statusCode", code, "clientMessage", message, "error", err}, fields...)...)
		paramsFields := map[string]interface{}{}
		if err := mapstructure.Decode(params, &paramsFields); err == nil {
			log.RequestIDLogger(r).Debug(paramsFields)
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
			return entries.NewCreateLogEntryDefault(code).WithPayload(errorMsg(message, code))
		}
	case entries.SearchLogQueryParams:
		logMsg(params.HTTPRequest)
		switch code {
		case http.StatusBadRequest:
			return entries.NewSearchLogQueryBadRequest().WithPayload(errorMsg(message, code))
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
	case tlog.GetPublicKeyParams:
		logMsg(params.HTTPRequest)
		return tlog.NewGetPublicKeyDefault(code).WithPayload(errorMsg(message, code))
	case index.SearchIndexParams:
		logMsg(params.HTTPRequest)
		switch code {
		case http.StatusBadRequest:
			return index.NewSearchIndexBadRequest().WithPayload(errorMsg(message, code))
		default:
			return index.NewSearchIndexDefault(code).WithPayload(errorMsg(message, code))
		}
	case timestamp.GetTimestampResponseParams:
		logMsg(params.HTTPRequest)
		switch code {
		case http.StatusBadRequest:
			return timestamp.NewGetTimestampResponseBadRequest().WithPayload(errorMsg(message, code))
		case http.StatusNotImplemented:
			return timestamp.NewGetTimestampResponseNotImplemented()
		default:
			return timestamp.NewGetTimestampResponseDefault(code).WithPayload(errorMsg(message, code))
		}
	case timestamp.GetTimestampCertChainParams:
		logMsg(params.HTTPRequest)
		switch code {
		case http.StatusNotFound:
			return timestamp.NewGetTimestampCertChainNotFound()
		default:
			return timestamp.NewGetTimestampCertChainDefault(code).WithPayload(errorMsg(message, code))
		}
	default:
		log.Logger.Errorf("unable to find method for type %T; error: %v", params, err)
		return middleware.Error(http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
	}
}
