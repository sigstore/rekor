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

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sigstore/rekor/pkg/client"
)

type unusedIndexClient struct{}

func (unusedIndexClient) idempotentAddToIndex(context.Context, string, string) error { return nil }

func TestPopulateWaitsForAllErrorResults(t *testing.T) {
	oldStart, oldEnd, oldConcurrency := *startIndex, *endIndex, *concurrency
	t.Cleanup(func() { *startIndex, *endIndex, *concurrency = oldStart, oldEnd, oldConcurrency })
	*startIndex, *endIndex, *concurrency = 0, 99, 8
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"uuid":{"body":"invalid-base64","logID":"abc","logIndex":0,"integratedTime":1}}`)
	}))
	defer server.Close()
	rekor, err := client.GetRekorClient(server.URL, client.WithRetryCount(0))
	if err != nil {
		t.Fatal(err)
	}
	err = populate(unusedIndexClient{}, rekor)
	if err == nil || !strings.Contains(err.Error(), "failed to parse 100 entries") {
		t.Fatalf("lost collected errors: %v", err)
	}
}

type failingIndexClient struct{}

func (failingIndexClient) idempotentAddToIndex(context.Context, string, string) error {
	return errors.New("injected insert failure")
}
func TestPopulateConcurrentInsertFailures(t *testing.T) {
	oldStart, oldEnd, oldConcurrency := *startIndex, *endIndex, *concurrency
	t.Cleanup(func() { *startIndex, *endIndex, *concurrency = oldStart, oldEnd, oldConcurrency })
	*startIndex, *endIndex, *concurrency = 0, 99, 8
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	sig, err := ecdsa.SignASN1(rand.Reader, key, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	entry := fmt.Sprintf(`{"kind":"hashedrekord","apiVersion":"0.0.1","spec":{"data":{"hash":{"algorithm":"sha256","value":"%s"}},"signature":{"content":"%s","publicKey":{"content":"%s"}}}}`, strings.Repeat("0", 64), base64.StdEncoding.EncodeToString(sig), pub)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"uuid":{"body":"%s","logID":"abc","logIndex":0,"integratedTime":1}}`, base64.StdEncoding.EncodeToString([]byte(entry)))
	}))
	defer server.Close()
	rekor, err := client.GetRekorClient(server.URL, client.WithRetryCount(0))
	if err != nil {
		t.Fatal(err)
	}
	err = populate(failingIndexClient{}, rekor)
	if err == nil || !strings.Contains(err.Error(), "too many insertion errors") || !strings.Contains(err.Error(), "failed to insert/remove") {
		t.Fatalf("lost worker or collector errors: %v", err)
	}
}
