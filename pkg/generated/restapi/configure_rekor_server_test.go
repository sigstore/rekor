/*
Copyright © 2025 The Sigstore Authors.

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

package restapi

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-openapi/errors"
)

// readBodyHandler reads the whole request body and, if the read fails, routes
// the error through logAndServeError exactly like the go-openapi runtime does
// when a consumer fails to read an oversized body. This lets the test exercise
// the full middleware + error-handling path without standing up the API server.
func readBodyHandler(wrapReason func(error) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			if wrapReason != nil {
				err = wrapReason(err)
			}
			logAndServeError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

func TestMaxBodySizeReturns413(t *testing.T) {
	const limit = 1024

	cases := []struct {
		name string
		// wrapReason mirrors how the read error is wrapped before it reaches
		// logAndServeError. nil means the bare *http.MaxBytesError is passed.
		wrapReason func(error) error
	}{
		{
			name:       "bare MaxBytesError",
			wrapReason: nil,
		},
		{
			name: "wrapped in ParseError (go-openapi consumer shape)",
			wrapReason: func(reason error) error {
				return errors.NewParseError("body", "", "", reason)
			},
		},
		{
			name: "wrapped in CompositeError of ParseError",
			wrapReason: func(reason error) error {
				return &errors.CompositeError{
					Errors: []error{errors.NewParseError("body", "", "", reason)},
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := maxBodySize(limit, readBodyHandler(tc.wrapReason))

			body := strings.NewReader(strings.Repeat("a", limit*4))
			req := httptest.NewRequest(http.MethodPost, "/api/v1/log/entries", body)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("expected status %d, got %d (body: %q)",
					http.StatusRequestEntityTooLarge, rec.Code, rec.Body.String())
			}
			// The message must name the configured limit so operators and
			// clients can see why the request was rejected (issue #2808).
			if want := fmt.Sprintf("%d", limit); !strings.Contains(rec.Body.String(), want) {
				t.Errorf("expected response body to name the limit %q, got %q", want, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "max_request_body_size") {
				t.Errorf("expected response body to reference max_request_body_size, got %q", rec.Body.String())
			}
		})
	}
}

// TestMaxBodySizeUnderLimitPasses guards against false positives: a request
// within the limit must not be turned into a 413.
func TestMaxBodySizeUnderLimitPasses(t *testing.T) {
	const limit = 1024
	handler := maxBodySize(limit, readBodyHandler(nil))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/log/entries", strings.NewReader("small body"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d for under-limit body, got %d", http.StatusOK, rec.Code)
	}
}

// TestAsMaxBytesError checks the detection helper directly across the shapes the
// error can take, including a non-matching error that must not be misclassified.
func TestAsMaxBytesError(t *testing.T) {
	mbErr := &http.MaxBytesError{Limit: 42}

	t.Run("bare", func(t *testing.T) {
		if got := asMaxBytesError(mbErr); got == nil || got.Limit != 42 {
			t.Fatalf("expected MaxBytesError with limit 42, got %v", got)
		}
	})

	t.Run("parse error reason", func(t *testing.T) {
		err := errors.NewParseError("body", "", "", mbErr)
		if got := asMaxBytesError(err); got == nil || got.Limit != 42 {
			t.Fatalf("expected MaxBytesError with limit 42, got %v", got)
		}
	})

	t.Run("composite of parse error", func(t *testing.T) {
		err := &errors.CompositeError{Errors: []error{errors.NewParseError("body", "", "", mbErr)}}
		if got := asMaxBytesError(err); got == nil || got.Limit != 42 {
			t.Fatalf("expected MaxBytesError with limit 42, got %v", got)
		}
	})

	t.Run("unrelated error is not matched", func(t *testing.T) {
		if got := asMaxBytesError(fmt.Errorf("some other failure")); got != nil {
			t.Fatalf("expected nil for unrelated error, got %v", got)
		}
	})
}
