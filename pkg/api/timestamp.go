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
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/go-openapi/runtime/middleware"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/timestamp"
)

func RequestFromURL(ctx context.Context, request []byte, url string) ([]byte, error) {
	client := &http.Client{}
	httpRequest, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(request))
	if err != nil {
		return nil, err
	}

	httpRequest.Header.Set("Content-Type", "application/timestamp-query")

	resp, err := client.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error fetching from TSA %d: %s", resp.StatusCode, resp.Status)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	return body, nil
}

func TimestampResponseHandler(params timestamp.GetTimestampResponseParams) middleware.Responder {
	httpReqCtx := params.HTTPRequest.Context()

	// TODO: Add support for in-house timestamp response if JSONRequest (or RFC 3161).
	resp, err := RequestFromURL(httpReqCtx, params.Query.RfcRequest, params.Query.URL.String())
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, err, failedToGenerateTimestampResponse)
	}

	// TODO: Add optional to upload to transparency log and add to response.
	timestampResponse := new(models.TimestampResponse)
	timestampResponse.RfcResponse = resp
	return timestamp.NewGetTimestampResponseOK().WithPayload(timestampResponse)
}
