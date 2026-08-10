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

package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRetryTransport(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		maxRetries   int
		statusCodes  []int
		expectStatus int
		expectErrors int
	}{
		{
			name:         "success on first try",
			maxRetries:   3,
			statusCodes:  []int{200},
			expectStatus: 200,
			expectErrors: 0,
		},
		{
			name:         "success on second try",
			maxRetries:   3,
			statusCodes:  []int{500, 200},
			expectStatus: 200,
			expectErrors: 1, // one 500
		},
		{
			name:         "fail all retries",
			maxRetries:   2,
			statusCodes:  []int{503, 503, 503},
			expectStatus: 503,
			expectErrors: 3,
		},
		{
			name:         "retry on 429",
			maxRetries:   2,
			statusCodes:  []int{429, 200},
			expectStatus: 200,
			expectErrors: 1, // one 429
		},
		{
			name:         "don't retry on 4xx",
			maxRetries:   3,
			statusCodes:  []int{404},
			expectStatus: 404,
			expectErrors: 0, // 404 is returned immediately
		},
		{
			name:         "don't retry on 501",
			maxRetries:   3,
			statusCodes:  []int{501},
			expectStatus: 501,
			expectErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tryCount := 0
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				status := tt.statusCodes[tryCount]
				tryCount++

				w.WriteHeader(status)

				// Read body to test body replay
				body, _ := io.ReadAll(r.Body)
				if len(body) > 0 && string(body) != "request body" {
					t.Errorf("expected body 'request body', got %q", string(body))
				}
			}))
			defer ts.Close()

			rt := &retryTransport{
				Transport:    http.DefaultTransport,
				MaxRetries:   uint(tt.maxRetries),
				RetryWaitMin: 1 * time.Millisecond,
				RetryWaitMax: 5 * time.Millisecond,
			}

			req, err := http.NewRequest(http.MethodPost, ts.URL, bytes.NewBufferString("request body"))
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			resp, err := rt.RoundTrip(req)
			if tt.expectStatus == 0 {
				if err == nil {
					t.Errorf("expected error, got nil (status %d)", resp.StatusCode)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				} else if resp.StatusCode != tt.expectStatus {
					t.Errorf("expected status %d, got %d", tt.expectStatus, resp.StatusCode)
				}
			}

			if tryCount != tt.expectErrors+1 && tryCount != len(tt.statusCodes) {
				t.Errorf("expected %d or %d tries, got %d", tt.expectErrors+1, len(tt.statusCodes), tryCount)
			}
		})
	}
}

func TestRetryTransportContextCancel(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
	}))
	defer ts.Close()

	rt := &retryTransport{
		Transport:    http.DefaultTransport,
		MaxRetries:   3,
		RetryWaitMin: 100 * time.Millisecond,
		RetryWaitMax: 200 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err = rt.RoundTrip(req)
	if err == nil {
		t.Errorf("expected error, got nil")
	} else if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestRetryErrorHandler(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	customErr := io.ErrUnexpectedEOF
	handlerCalled := false

	rt := &retryTransport{
		Transport:    http.DefaultTransport,
		MaxRetries:   1,
		RetryWaitMin: 1 * time.Millisecond,
		RetryWaitMax: 2 * time.Millisecond,
		ErrorHandler: func(resp *http.Response, _ error, numTries uint) (*http.Response, error) {
			handlerCalled = true
			if numTries != 2 {
				t.Errorf("expected 2 tries, got %d", numTries)
			}
			return resp, customErr
		},
	}

	req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	_, err = rt.RoundTrip(req)
	if err != customErr {
		t.Errorf("expected custom error, got %v", err)
	}
	if !handlerCalled {
		t.Errorf("expected ErrorHandler to be called")
	}
}

type testLogger struct {
	messages []string
}

func (l *testLogger) Printf(format string, args ...any) {
	l.messages = append(l.messages, fmt.Sprintf(format, args...))
}

type testLeveledLogger struct {
	debugs []string
	errors []string
}

func (l *testLeveledLogger) Error(msg string, keysAndValues ...any) {
	l.errors = append(l.errors, fmt.Sprintf("%s %v", msg, keysAndValues))
}

func (l *testLeveledLogger) Info(_ string, _ ...any) {}

func (l *testLeveledLogger) Debug(msg string, keysAndValues ...any) {
	l.debugs = append(l.debugs, fmt.Sprintf("%s %v", msg, keysAndValues))
}

func (l *testLeveledLogger) Warn(_ string, _ ...any) {}

func TestRetryTransportLogger(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	t.Run("Standard Logger", func(t *testing.T) {
		logger := &testLogger{}
		rt := &retryTransport{
			Transport:    http.DefaultTransport,
			MaxRetries:   1,
			RetryWaitMin: 1 * time.Millisecond,
			RetryWaitMax: 2 * time.Millisecond,
			Logger:       logger,
		}

		req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		_, _ = rt.RoundTrip(req)

		if len(logger.messages) < 2 {
			t.Errorf("expected at least 2 log messages, got %d", len(logger.messages))
		}
	})

	t.Run("Leveled Logger", func(t *testing.T) {
		logger := &testLeveledLogger{}
		rt := &retryTransport{
			Transport:    http.DefaultTransport,
			MaxRetries:   1,
			RetryWaitMin: 1 * time.Millisecond,
			RetryWaitMax: 2 * time.Millisecond,
			Logger:       logger,
		}

		req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		_, _ = rt.RoundTrip(req)

		if len(logger.debugs) < 2 {
			t.Errorf("expected at least 2 debug messages, got %d", len(logger.debugs))
		}
	})
}

func TestRetryAfterHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		headerFunc func() string
	}{
		{
			name: "Seconds format",
			headerFunc: func() string {
				return "1"
			},
		},
		{
			name: "Date format",
			headerFunc: func() string {
				// Add 2 seconds to ensure truncation in http.TimeFormat
				// still results in a wait of at least 1 second.
				return time.Now().Add(2 * time.Second).UTC().Format(http.TimeFormat)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tryCount := 0
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				tryCount++
				if tryCount == 1 {
					w.Header().Set("Retry-After", tt.headerFunc())
					w.WriteHeader(http.StatusTooManyRequests)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer ts.Close()

			rt := &retryTransport{
				Transport:    http.DefaultTransport,
				MaxRetries:   1,
				RetryWaitMin: 1 * time.Millisecond,
				RetryWaitMax: 2 * time.Second, // Increased to allow the 1s Retry-After header
			}

			req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			start := time.Now()
			_, _ = rt.RoundTrip(req)
			elapsed := time.Since(start)

			if elapsed < 1*time.Second {
				t.Errorf("expected to wait at least 1s due to Retry-After, but took %v", elapsed)
			}
			if tryCount != 2 {
				t.Errorf("expected 2 tries, got %d", tryCount)
			}
		})
	}
}

type testUnrecoverableTransport struct {
	tries int
}

func (t *testUnrecoverableTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.tries++
	return nil, fmt.Errorf("unsupported protocol scheme")
}

func TestUnrecoverableError(t *testing.T) {
	t.Parallel()

	transport := &testUnrecoverableTransport{}
	rt := &retryTransport{
		Transport:    transport,
		MaxRetries:   3,
		RetryWaitMin: 1 * time.Millisecond,
		RetryWaitMax: 2 * time.Millisecond,
	}

	req, err := http.NewRequest(http.MethodGet, "http://test", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	_, err = rt.RoundTrip(req)

	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	if transport.tries != 1 {
		t.Errorf("expected 1 try for unrecoverable error, got %d", transport.tries)
	}
}

func TestRetryGetBodyError(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
	}))
	defer ts.Close()

	rt := &retryTransport{
		Transport:    http.DefaultTransport,
		MaxRetries:   3,
		RetryWaitMin: 1 * time.Millisecond,
		RetryWaitMax: 2 * time.Millisecond,
	}

	req, err := http.NewRequest(http.MethodPost, ts.URL, bytes.NewBufferString("first body"))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	expectedErr := fmt.Errorf("simulated GetBody error")
	req.GetBody = func() (io.ReadCloser, error) {
		return nil, expectedErr
	}

	_, err = rt.RoundTrip(req)
	if err != expectedErr {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
}

type closeTrackingBody struct {
	closed bool
}

func (b *closeTrackingBody) Read(_ []byte) (n int, err error) {
	return 0, io.EOF
}

func (b *closeTrackingBody) Close() error {
	b.closed = true
	return nil
}

type mockTransport struct {
	body *closeTrackingBody
}

func (m *mockTransport) RoundTrip(*http.Request) (*http.Response, error) {
	m.body = &closeTrackingBody{}
	return &http.Response{
		StatusCode: 500,
		Body:       m.body,
	}, nil
}

func TestRetryErrorHandlerClosesBody(t *testing.T) {
	t.Parallel()

	mt := &mockTransport{}
	rt := &retryTransport{
		Transport:    mt,
		MaxRetries:   0,
		RetryWaitMin: 1 * time.Millisecond,
		RetryWaitMax: 2 * time.Millisecond,
		ErrorHandler: func(_ *http.Response, _ error, _ uint) (*http.Response, error) {
			// Deliberately return nil response to trigger the leak cleanup
			return nil, fmt.Errorf("custom error")
		},
	}

	req, _ := http.NewRequest(http.MethodGet, "http://test", nil)
	_, _ = rt.RoundTrip(req)

	if mt.body == nil || !mt.body.closed {
		t.Errorf("expected response body to be closed by transport when ErrorHandler drops it")
	}
}

type mockContextTransport struct {
	cancel context.CancelFunc
}

func (m *mockContextTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	m.cancel()
	<-req.Context().Done()
	return nil, fmt.Errorf("url error: %w", req.Context().Err())
}

func TestRetryContextErrorPreserved(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	rt := &retryTransport{
		Transport:  &mockContextTransport{cancel: cancel},
		MaxRetries: 3,
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://test", nil)

	_, err := rt.RoundTrip(req)
	if err == nil || !strings.Contains(err.Error(), "url error") {
		t.Errorf("expected original error to be preserved, got %v", err)
	}
}

func TestRetryContextCancelLeaksBody(t *testing.T) {
	t.Parallel()

	rt := &retryTransport{
		Transport:  http.DefaultTransport,
		MaxRetries: 3,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://test", nil)

	tc := &closeTrackingBody{}
	req.GetBody = func() (io.ReadCloser, error) {
		return tc, nil
	}
	req.Body = tc

	_, err := rt.RoundTrip(req)
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}

	if !tc.closed {
		t.Errorf("expected GetBody to be closed when returning early due to context cancellation")
	}
}

func TestRetryContextCancelLeaksDynamicBody(t *testing.T) {
	t.Parallel()

	rt := &retryTransport{
		Transport:  http.DefaultTransport,
		MaxRetries: 3,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://test", nil)

	tc1 := &closeTrackingBody{}
	tc2 := &closeTrackingBody{}

	callCount := 0
	req.GetBody = func() (io.ReadCloser, error) {
		callCount++
		if callCount == 1 {
			return tc2, nil
		}
		return nil, fmt.Errorf("should not be called more than once")
	}
	req.Body = tc1

	_, err := rt.RoundTrip(req)
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}

	if !tc1.closed {
		t.Errorf("expected original Body (tc1) to be closed")
	}
	if !tc2.closed {
		t.Errorf("expected cloned Body (tc2) to be closed when returning early")
	}
}
