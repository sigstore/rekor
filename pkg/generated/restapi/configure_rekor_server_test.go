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

package restapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServeStaticContent(t *testing.T) {
	t.Parallel()

	fallbackHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	handler := serveStaticContent(fallbackHandler)

	tests := []struct {
		name            string
		path            string
		wantStatus      int
		wantContentType string
		wantBody        []byte
	}{
		{
			name:            "home page",
			path:            "/",
			wantStatus:      http.StatusOK,
			wantContentType: "text/html",
			wantBody:        homePageBytes,
		},
		{
			name:            "robots.txt",
			path:            "/robots.txt",
			wantStatus:      http.StatusOK,
			wantContentType: "text/plain; charset=utf-8",
			wantBody:        []byte("User-agent: *\nDisallow: /\n"),
		},
		{
			name:       "fallback for other paths",
			path:       "/api/v1/log",
			wantStatus: http.StatusTeapot,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if tc.wantContentType != "" {
				if got := rec.Header().Get("Content-Type"); got != tc.wantContentType {
					t.Errorf("Content-Type = %q, want %q", got, tc.wantContentType)
				}
			}
			if tc.wantBody != nil {
				if !bytes.Equal(rec.Body.Bytes(), tc.wantBody) {
					t.Errorf("body = %q, want %q", rec.Body.String(), string(tc.wantBody))
				}
			}
		})
	}
}
