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

package util

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// closeTrackingTransport records whether the body of each response it hands
// out was closed.
type closeTrackingTransport struct {
	base   http.RoundTripper
	closed atomic.Bool
}

type trackedBody struct {
	io.ReadCloser
	closed *atomic.Bool
}

func (b *trackedBody) Close() error {
	b.closed.Store(true)
	return b.ReadCloser.Close()
}

func (t *closeTrackingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &trackedBody{ReadCloser: resp.Body, closed: &t.closed}
	return resp, nil
}

// FileOrURLReadCloser builds its own http.Client with no Transport, so it
// uses http.DefaultTransport; swap that for the tracking one for this test.
func trackDefaultTransport(t *testing.T) *closeTrackingTransport {
	t.Helper()
	tracker := &closeTrackingTransport{base: http.DefaultTransport}
	orig := http.DefaultTransport
	http.DefaultTransport = tracker
	t.Cleanup(func() { http.DefaultTransport = orig })
	return tracker
}

func TestFileOrURLReadCloserClosesBodyOnErrorStatus(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusInternalServerError, http.StatusMovedPermanently} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if status == http.StatusMovedPermanently {
					// A redirect with no Location is returned to the caller as-is.
					w.WriteHeader(status)
					return
				}
				http.Error(w, "nope", status)
			}))
			defer srv.Close()
			tracker := trackDefaultTransport(t)

			rc, err := FileOrURLReadCloser(context.Background(), srv.URL, nil)
			if err == nil {
				rc.Close()
				t.Fatalf("expected an error for status %d", status)
			}
			if rc != nil {
				t.Fatalf("expected no reader on error, got %T", rc)
			}
			if !tracker.closed.Load() {
				t.Fatalf("response body was not closed for status %d", status)
			}
		})
	}
}

func TestFileOrURLReadCloserReturnsOpenBodyOnSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("artifact"))
	}))
	defer srv.Close()
	tracker := trackDefaultTransport(t)

	rc, err := FileOrURLReadCloser(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = rc.Close() })
	if tracker.closed.Load() {
		t.Fatal("body was closed before the caller read it")
	}
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if string(got) != "artifact" {
		t.Fatalf("got %q, want %q", got, "artifact")
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("closing body: %v", err)
	}
	if !tracker.closed.Load() {
		t.Fatal("caller's Close did not reach the response body")
	}
}

func TestFileOrURLReadCloserReadsContentWithoutURL(t *testing.T) {
	rc, err := FileOrURLReadCloser(context.Background(), "", []byte("local"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading content: %v", err)
	}
	if string(got) != "local" {
		t.Fatalf("got %q, want %q", got, "local")
	}
}
