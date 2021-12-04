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

	"github.com/spf13/viper"
)

func TestAPIKey(t *testing.T) {
	t.Parallel()
	pkRequestReceived := false
	logRequestReceived := false
	testServer := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			file := []byte{}

			switch {
			case strings.HasPrefix(r.URL.Path, "/api/v1/log/publicKey"):
				pkRequestReceived = true
				if r.URL.Query().Get("apiKey") != "" {
					t.Errorf("API key sent but not expected: %v", r.URL.Query().Get("apiKey"))
				}
			case strings.HasPrefix(r.URL.Path, "/api/v1/log"):
				logRequestReceived = true
				if r.URL.Query().Get("apiKey") == "" {
					t.Errorf("API key expected but not sent")
				}
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(file)
		}))
	defer testServer.Close()

	t.Run("GetLogInfo", func(t *testing.T) {
		logRequestReceived = false
		viper.Set("api-key", "thisIsAnAPIKey")
		client, err := GetRekorClient(testServer.URL)
		if err != nil {
			t.Error(err)
		}
		_, _ = client.Tlog.GetLogInfo(nil)
		if !logRequestReceived {
			t.Fatal("no GetLogInfo requests were received")
		}
	})

	t.Run("GetPublicKey", func(t *testing.T) {
		pkRequestReceived = false
		viper.Set("api-key", "")
		client, err := GetRekorClient(testServer.URL)
		if err != nil {
			t.Error(err)
		}
		_, _ = client.Pubkey.GetPublicKey(nil)
		if !pkRequestReceived {
			t.Fatal("no GetPublicKey requests were received")
		}

	})

}

func TestGetRekorClientWithOptions(t *testing.T) {
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
