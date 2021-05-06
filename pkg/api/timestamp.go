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
	"fmt"
	"net/http"

	"github.com/go-openapi/runtime/middleware"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/timestamp"
	pki "github.com/sigstore/rekor/pkg/pki/x509"
	"github.com/sigstore/rekor/pkg/util"
)

func RequestFromRekor(ctx context.Context, requestBytes []byte) ([]byte, error) {
	// Fail early if we don't haven't configured rekor with a certificate for timestamping.
	if len(api.certChain) == 0 {
		return nil, fmt.Errorf("rekor is not configured to serve timestamps")
	}

	req, err := util.ParseTimestampRequest(requestBytes)
	if err != nil {
		return nil, err
	}

	resp, err := util.CreateResponse(ctx, *req, api.certChain, api.signer)
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
	ctx := params.HTTPRequest.Context()

	// TODO: Add support for in-house JSON based timestamp response.
	resp, err := RequestFromRekor(ctx, params.Query.RfcRequest)
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, err, failedToGenerateTimestampResponse)
	}

	// TODO: Add upload to transparency log.
	timestampResponse := new(models.TimestampResponse)
	timestampResponse.RfcResponse = resp
	return timestamp.NewGetTimestampResponseOK().WithPayload(timestampResponse)
}

func GetTimestampCertChainHandler(params timestamp.GetTimestampCertChainParams) middleware.Responder {
	certChainBytes, err := pki.CertChainToPEM(api.certChain)
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("PEM encoding error: %w", err), "")

	}
	return timestamp.NewGetTimestampCertChainOK().WithPayload(string(certChainBytes))
}
