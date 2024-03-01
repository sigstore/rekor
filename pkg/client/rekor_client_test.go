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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/rekor/pkg/generated/client/index"
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
	_, _ = client.Tlog.GetLogInfo(nil)
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
	_, _ = client.Tlog.GetLogInfo(nil)
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

	client, err := GetRekorClient(testServer.URL, WithRetryCount(2))
	if err != nil {
		t.Error(err)
	}
	_, err = client.Tlog.GetLogInfo(nil)
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
