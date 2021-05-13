/*
Copyright The Rekor Authors.

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
	"encoding/asn1"
	"io/ioutil"
	"net/http"

	"github.com/go-openapi/runtime/middleware"
	"github.com/pkg/errors"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/timestamp"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/util"
)

func RequestFromRekor(ctx context.Context, requestBytes []byte) ([]byte, error) {
	req, err := util.ParseTimestampRequest(requestBytes)
	if err != nil {
		return nil, err
	}

	resp, err := util.CreateRfc3161Response(ctx, *req, api.certChain, api.signer)
	if err != nil {
		return nil, err
	}

	body, err := asn1.Marshal(*resp)
	if err != nil {
		return nil, err
	}

	return body, nil
}

func TimestampResponseHandler(params timestamp.GetTimestampResponseParams) middleware.Responder {
	// Fail early if we don't haven't configured rekor with a certificate for timestamping.
	if len(api.certChain) == 0 {
		return handleRekorAPIError(params, http.StatusNotFound, errors.New("rekor is not configured to serve timestamps"), "")
	}

	// TODO: Add support for in-house JSON based timestamp response.
	request, err := ioutil.ReadAll(params.Request)
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, err, failedToGenerateTimestampResponse)
	}

	ctx := params.HTTPRequest.Context()
	resp, err := RequestFromRekor(ctx, request)
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, err, failedToGenerateTimestampResponse)
	}

	// TODO: Upload to transparency log and add entry UUID to location header.
	log.RequestIDLogger(params.HTTPRequest).Debug("generating ok")
	return timestamp.NewGetTimestampResponseOK().WithPayload(string(resp))
}

func GetTimestampCertChainHandler(params timestamp.GetTimestampCertChainParams) middleware.Responder {
	return timestamp.NewGetTimestampCertChainOK().WithPayload(api.certChainPem)
}
