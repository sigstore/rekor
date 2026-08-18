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
	"fmt"
	"net/http"
	"regexp"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/entries"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/index"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/pubkey"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/tlog"
	"github.com/sigstore/rekor/pkg/log"
)

// statusClientClosedRequest is the nginx-style code for a client that hung up
// before we could respond; it has no net/http constant or StatusText entry.
const statusClientClosedRequest = 499

func mapGRPCToHTTP(code int, err error) int {
	// Only try to be smart if current code is a generic 500
	if code != http.StatusInternalServerError {
		return code
	}

	// FromError walks the whole error tree, so wrapped and joined errors resolve too.
	// The list of handled codes is intentionally limited to specific cases
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.Canceled:
			return statusClientClosedRequest
		case codes.DeadlineExceeded:
			return http.StatusGatewayTimeout
		}
	}
	return code
}

const (
	trillianCommunicationError     = "unexpected error communicating with transparency log"
	trillianUnexpectedResult       = "unexpected result from transparency log"
	clientDisconnected             = "client disconnected during request"
	validationError                = "error processing entry: %v"
	failedToGenerateCanonicalEntry = "error generating canonicalized entry"
	entryAlreadyExists             = "an equivalent entry already exists in the transparency log with UUID %v"
	firstSizeLessThanLastSize      = "firstSize(%d) must be less than lastSize(%d)"
	malformedUUID                  = "UUID must be a 64-character hexadecimal string"
	malformedPublicKey             = "public key provided could not be parsed"
	failedToGenerateCanonicalKey   = "error generating canonicalized public key"
	indexStorageUnexpectedResult   = "unexpected result from searching index"
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

var re = regexp.MustCompile("^(.*)Params$")

func handleRekorAPIError(params any, code int, err error, message string, fields ...any) middleware.Responder {
	code = mapGRPCToHTTP(code, err)

	if message == "" {
		// http.StatusText has no entry for the nonstandard 499
		if code == statusClientClosedRequest {
			message = clientDisconnected
		} else {
			message = http.StatusText(code)
		}
	}

	typeStr := fmt.Sprintf("%T", params)
	handler := re.FindStringSubmatch(typeStr)[1]

	logMsg := func(r *http.Request, inputs ...any) {
		ctx := r.Context()
		// If the client disconnected before we could respond, rewrite the
		// status to 499 (nginx-style "client closed request") so that the
		// response, request log, and metrics all agree that this wasn't a
		// server-side error we could have prevented. Also replace the
		// client-facing message so the JSON body reflects the true cause.
		if code >= 500 && ctx.Err() == context.Canceled {
			code = statusClientClosedRequest
			message = clientDisconnected
		}
		fields := append([]any{"handler", handler, "statusCode", code, "clientMessage", message}, fields...)
		if code >= 500 {
			fields = append(fields, inputs...)
			log.ContextLogger(ctx).Errorw(err.Error(), fields...)
		} else {
			log.ContextLogger(ctx).Warnw(err.Error(), fields...)
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
			requestFields := []any{"requestBody", params.ProposedEntry}
			logMsg(params.HTTPRequest, requestFields...)
			return entries.NewCreateLogEntryDefault(code).WithPayload(errorMsg(message, code))
		}
	case entries.SearchLogQueryParams:
		requestFields := []any{}
		if params.Entry != nil {
			requestFields = append(requestFields, "requestBody", *params.Entry)
		}
		logMsg(params.HTTPRequest, requestFields...)
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
		requestFields := []any{}
		if params.Query != nil {
			requestFields = append(requestFields, "requestBody", *params.Query)
		}
		logMsg(params.HTTPRequest, requestFields...)
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
