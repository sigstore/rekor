//
// Copyright 2026 The Sigstore Authors.
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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/entries"
)

func TestHandleRekorAPIError_ClientCanceled(t *testing.T) {
	// Case 1: When client context is NOT canceled, we expect a standard HTTP 500 response.
	t.Run("Context not canceled returns 500", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/log/entries?logIndex=1", nil)
		params := entries.GetLogEntryByIndexParams{
			HTTPRequest: req,
			LogIndex:    1,
		}

		responder := handleRekorAPIError(params, http.StatusInternalServerError, errors.New("underlying error"), "some server error message")

		recorder := httptest.NewRecorder()
		responder.WriteResponse(recorder, runtime.JSONProducer())

		if recorder.Code != http.StatusInternalServerError {
			t.Errorf("Expected status code %d, got %d", http.StatusInternalServerError, recorder.Code)
		}
	})

	// Case 2: When client context IS canceled (simulating a disconnect), we expect HTTP 499.
	t.Run("Context canceled returns 499", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel the context to simulate client disconnect mid-flight

		req := httptest.NewRequest("GET", "/api/v1/log/entries?logIndex=1", nil).WithContext(ctx)
		params := entries.GetLogEntryByIndexParams{
			HTTPRequest: req,
			LogIndex:    1,
		}

		responder := handleRekorAPIError(params, http.StatusInternalServerError, errors.New("underlying error"), "some server error message")

		recorder := httptest.NewRecorder()
		responder.WriteResponse(recorder, runtime.JSONProducer())

		if recorder.Code != 499 {
			t.Errorf("Expected status code 499, got %d", recorder.Code)
		}
	})
}
