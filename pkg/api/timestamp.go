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
	"bytes"
	"context"
	"encoding/asn1"
	"io/ioutil"
	"net/http"

	"github.com/go-openapi/runtime/middleware"
	"github.com/pkg/errors"
	"github.com/sassoftware/relic/lib/pkcs9"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/timestamp"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/util"
)

func RequestFromRekor(ctx context.Context, req pkcs9.TimeStampReq) ([]byte, error) {
	resp, err := util.CreateRfc3161Response(ctx, req, api.certChain, api.signer)
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
		return handleRekorAPIError(params, http.StatusNotImplemented, errors.New("rekor is not configured to serve timestamps"), "")
	}

	// TODO: Add support for in-house JSON based timestamp response.
	requestBytes, err := ioutil.ReadAll(params.Request)
	if err != nil {
		return handleRekorAPIError(params, http.StatusBadRequest, err, failedToGenerateTimestampResponse)
	}
	req, err := util.ParseTimestampRequest(requestBytes)
	if err != nil {
		return handleRekorAPIError(params, http.StatusBadRequest, err, failedToGenerateTimestampResponse)
	}

	// Create response
	ctx := params.HTTPRequest.Context()
	resp, err := RequestFromRekor(ctx, *req)
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, err, failedToGenerateTimestampResponse)
	}

	// TODO: Upload to transparency log and add entry UUID to location header.
	log.Logger.Errorf("generated OK")
	return timestamp.NewGetTimestampResponseOK().WithPayload(ioutil.NopCloser(bytes.NewReader(resp)))
}

func GetTimestampCertChainHandler(params timestamp.GetTimestampCertChainParams) middleware.Responder {
	return timestamp.NewGetTimestampCertChainOK().WithPayload(api.certChainPem)
}
