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

package client

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/client/tlog"
	"go.uber.org/goleak"
)

func TestGetRekorClientWithUserAgent(t *testing.T) {
	t.Parallel()
	expectedUserAgent := "test User-Agent"
	requestReceived := false
	testServer := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requestReceived = true
			file := []byte{}

			got := r.UserAgent()
			if got != expectedUserAgent {
				t.Errorf("wanted User-Agent %q, got %q", expectedUserAgent, got)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(file)
		}))
	defer testServer.Close()

	client, err := GetRekorClient(testServer.URL, WithUserAgent(expectedUserAgent))
	if err != nil {
		t.Error(err)
	}
	_, _ = client.Tlog.GetLogInfo(tlog.NewGetLogInfoParams())
	if !requestReceived {
		t.Fatal("no requests were received")
	}
}

func TestGetRekorClientWithCustomPath(t *testing.T) {
	t.Parallel()
	requestReceived := false
	pathAdd := "/custom"

	testServer := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requestReceived = true
			if !strings.HasPrefix(r.URL.Path, pathAdd) {
				t.Errorf("Expected request to be sent to /test, got %s", r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
		}))
	defer testServer.Close()

	testServer.URL += pathAdd

	client, err := GetRekorClient(testServer.URL)
	if err != nil {
		t.Error(err)
	}
	_, _ = client.Tlog.GetLogInfo(tlog.NewGetLogInfoParams())
	if !requestReceived {
		t.Fatal("no requests were received")
	}
}

func TestGetRekorClientWithRetryCount(t *testing.T) {
	t.Parallel()
	expectedCount := 2
	actualCount := 0
	testServer := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			actualCount++
			file := []byte{}

			if actualCount < expectedCount {
				w.WriteHeader(http.StatusInternalServerError)
			} else {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(file)
			}
		}))
	defer testServer.Close()

	client, err := GetRekorClient(testServer.URL, WithRetryCount(2), WithRetryWaitMin(0))
	if err != nil {
		t.Error(err)
	}
	_, err = client.Tlog.GetLogInfo(tlog.NewGetLogInfoParams())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRekorLeakedGoroutine_SearchByHash(t *testing.T) {
	testServer := httptest.NewUnstartedServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			file := []byte("ok")

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(file)
		}))
	testServer.EnableHTTP2 = true
	testServer.StartTLS()
	// sleep to allow go routines to start
	time.Sleep(1 * time.Second)
	// store the goroutines launched by the testserver
	opt := goleak.IgnoreCurrent()
	defer func() {
		goleak.VerifyNone(t, opt)
		// this is done after leak detection so that we can test
		testServer.Close()
	}()
	rekor, _ := GetRekorClient(testServer.URL, WithInsecureTLS(true))
	rekor.Index.SearchIndex(index.NewSearchIndexParams())
}

func TestRetryErrorHandlerSurfacesServerResponse(t *testing.T) {
	// When retries exhaust against a server that keeps returning 5xx,
	// the final error must include the status code and body — not just
	// "giving up after N attempt(s)". See sigstore/rekor#2640.
	testServer := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("database unavailable"))
		}))
	defer testServer.Close()

	client, err := GetRekorClient(testServer.URL,
		WithRetryCount(1), WithRetryWaitMin(1*time.Millisecond), WithRetryWaitMax(2*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Tlog.GetLogInfo(tlog.NewGetLogInfoParams())
	if err == nil {
		t.Fatal("expected an error after retries were exhausted")
	}
	msg := err.Error()
	if !strings.Contains(msg, "status 500") {
		t.Errorf("expected error to include 'status 500', got: %s", msg)
	}
	if !strings.Contains(msg, "database unavailable") {
		t.Errorf("expected error to include server body 'database unavailable', got: %s", msg)
	}
}

type testLeveledLogger struct {
	buf bytes.Buffer
}

func (l *testLeveledLogger) Error(msg string, keysAndValues ...any) {
	fmt.Fprintf(&l.buf, "[ERROR] %s %v\n", msg, keysAndValues)
}
func (l *testLeveledLogger) Info(msg string, keysAndValues ...any) {
	fmt.Fprintf(&l.buf, "[INFO] %s %v\n", msg, keysAndValues)
}
func (l *testLeveledLogger) Debug(msg string, keysAndValues ...any) {
	fmt.Fprintf(&l.buf, "[DEBUG] %s %v\n", msg, keysAndValues)
}
func (l *testLeveledLogger) Warn(msg string, keysAndValues ...any) {
	fmt.Fprintf(&l.buf, "[WARN] %s %v\n", msg, keysAndValues)
}

func TestGetRekorClientWithLogger(t *testing.T) {
	t.Parallel()
	var calls int
	testServer := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			calls++
			if calls%2 == 1 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte{})
		}))
	defer testServer.Close()

	t.Run("standard logger", func(t *testing.T) {
		var buf bytes.Buffer
		stdLogger := log.New(&buf, "", 0)
		client, err := GetRekorClient(testServer.URL,
			WithRetryCount(2), WithRetryWaitMin(0), WithLogger(stdLogger))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Tlog.GetLogInfo(tlog.NewGetLogInfoParams()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		out := buf.String()
		if !strings.Contains(out, "[DEBUG] GET ") {
			t.Errorf("expected request debug log, got: %s", out)
		}
		if !strings.Contains(out, "retrying in") {
			t.Errorf("expected retry backoff debug log, got: %s", out)
		}
	})

	t.Run("leveled logger", func(t *testing.T) {
		lvlLogger := &testLeveledLogger{}
		client, err := GetRekorClient(testServer.URL,
			WithRetryCount(2), WithRetryWaitMin(0), WithLogger(lvlLogger))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Tlog.GetLogInfo(tlog.NewGetLogInfoParams()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		out := lvlLogger.buf.String()
		if !strings.Contains(out, "[DEBUG] performing request") {
			t.Errorf("expected performing request debug log, got: %s", out)
		}
		if !strings.Contains(out, "[DEBUG] retrying request") {
			t.Errorf("expected retrying request debug log, got: %s", out)
		}
	})
}
