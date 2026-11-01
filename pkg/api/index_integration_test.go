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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/entries"
	"github.com/sigstore/rekor/pkg/indexstorage/mysql"
	"github.com/spf13/viper"

	// Register the DSSE version exercised by the signed fan-out requests.
	_ "github.com/sigstore/rekor/pkg/types/dsse/v0.0.1"
	"google.golang.org/api/support/bundler"
)

func TestHTTPUploadFailsOpenWithIndexFailure(t *testing.T) {
	fixturePath := os.Getenv("REKOR_INDEX_TEST_FIXTURES")
	if fixturePath == "" {
		t.Skip("requires isolated Trillian on localhost:28090 and REKOR_INDEX_TEST_FIXTURES")
	}
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []json.RawMessage
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	if len(fixtures) < 3 {
		t.Fatal("requires at least three distinct signed fixtures")
	}
	viper.Set("trillian_log_server.address", "127.0.0.1")
	viper.Set("trillian_log_server.port", 28090)
	viper.Set("rekor_server.signer", "memory")
	viper.Set("rekor_server.hostname", "index-integration")
	t.Cleanup(viper.Reset)
	previous := api
	api, err = NewAPI(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = api.trillianClientManager.Close(); api = previous })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pe, err := models.UnmarshalProposedEntry(r.Body, runtime.JSONConsumer())
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		CreateLogEntryHandler(entries.CreateLogEntryParams{HTTPRequest: r, ProposedEntry: pe}).WriteResponse(w, runtime.JSONProducer())
	}))
	defer server.Close()
	client := &http.Client{Timeout: 15 * time.Second}
	for i, failure := range []error{bundler.ErrOverflow, bundler.ErrOversizedItem, errors.New("database unavailable")} {
		t.Run(failure.Error(), func(t *testing.T) {
			swapIndexStorage(t, &fakeIndexStorage{err: failure})
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL, bytes.NewReader(fixtures[i]))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			response, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, _ := io.ReadAll(response.Body)
			indexStorageWriters.Wait()
			if response.StatusCode != http.StatusCreated {
				t.Fatalf("upload rejected due to indexing failure: %d %s", response.StatusCode, body)
			}
			var entry models.LogEntry
			if err := json.Unmarshal(body, &entry); err != nil || len(entry) != 1 {
				t.Fatalf("invalid accepted entry: %s, %v", body, err)
			}
			for _, value := range entry {
				if value.Verification == nil || len(value.Verification.SignedEntryTimestamp) == 0 {
					t.Fatal("accepted entry lacks signed timestamp")
				}
			}
		})
	}
	t.Run("real_mysql_dsse_fanout", func(t *testing.T) {
		dsn := os.Getenv("REKOR_INDEX_TEST_DSN")
		if dsn == "" {
			t.Skip("requires disposable MySQL; run integration packages with -p 1")
		}
		provider, err := mysql.NewProvider(dsn, mysql.WithBatchDelay(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		defer provider.Shutdown() //nolint:errcheck
		swapIndexStorage(t, provider)
		verificationDB, err := sql.Open("mysql", dsn)
		if err != nil {
			t.Fatal(err)
		}
		defer verificationDB.Close()
		fanoutClient := &http.Client{Timeout: time.Minute}
		for _, tc := range []struct {
			name                 string
			count                int
			duplicate, materials bool
			wantRows             int
			lookup               string
		}{
			{"excessive_fanout", 250000, false, false, 0, "00000:0"},
			{"duplicate_fanout", 250000, true, false, 4, "00000:0"},
			{"large_slsa_provenance", 1500, false, true, 1504, fmt.Sprintf("sha256:%064x", 1499)},
		} {
			body := signedFanoutDSSE(t, tc.count, tc.duplicate, tc.materials)
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL, bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			response, err := fanoutClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			data, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != http.StatusCreated {
				t.Fatalf("%s: got %d: %s", tc.name, response.StatusCode, data)
			}
			var entries models.LogEntry
			if err := json.Unmarshal(data, &entries); err != nil || len(entries) != 1 {
				t.Fatalf("invalid response: %v", err)
			}
			provider.Flush()
			for id, entry := range entries {
				if entry.Verification == nil || len(entry.Verification.SignedEntryTimestamp) == 0 {
					t.Fatal("missing signed timestamp")
				}
				ids, err := provider.LookupIndices(context.Background(), []string{tc.lookup})
				if err != nil {
					t.Fatal(err)
				}
				if slices.Contains(ids, id) != (tc.wantRows > 0) {
					t.Fatalf("%s: index visibility did not match admission policy", tc.name)
				}
				var rows int
				if err := verificationDB.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM EntryIndex WHERE EntryUUID=?", id).Scan(&rows); err != nil {
					t.Fatal(err)
				}
				if rows != tc.wantRows {
					t.Fatalf("%s: got %d index rows, want %d", tc.name, rows, tc.wantRows)
				}
			}
		}
	})

}

// Use a fresh caller-generated key and a valid DSSE signature: fan-out must not
// turn an accepted log entry into an API failure, or prevent later indexing.
func signedFanoutDSSE(t *testing.T, count int, duplicate, materials bool) []byte {
	t.Helper()
	var subjects any
	statement := map[string]any{"_type": "https://in-toto.io/Statement/v0.1"}
	switch {
	case materials:
		items := make([]any, count)
		for i := range items {
			items[i] = map[string]any{"uri": fmt.Sprintf("pkg:generic/dependency-%d", i),
				"digest": map[string]string{"sha256": fmt.Sprintf("%064x", i)}}
		}
		statement["predicateType"] = "https://slsa.dev/provenance/v0.2"
		statement["predicate"] = map[string]any{"materials": items}
		subjects = []any{map[string]any{"name": "artifact", "digest": map[string]string{"sha256": strings.Repeat("a", 64)}}}
	case duplicate:
		items := make([]any, count)
		for i := range items {
			items[i] = map[string]any{"digest": map[string]string{"00000": "0"}}
		}
		subjects = items
	default:
		digests := make(map[string]string, count)
		for i := range count {
			digests[fmt.Sprintf("%05d", i)] = "0"
		}
		subjects = []any{map[string]any{"digest": digests}}
	}
	statement["subject"] = subjects
	payload, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const payloadType = "application/vnd.in-toto+json"
	hash := sha256.Sum256(dsse.PAE(payloadType, payload))
	sig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public})
	env, err := json.Marshal(dsse.Envelope{PayloadType: payloadType,
		Payload:    base64.StdEncoding.EncodeToString(payload),
		Signatures: []dsse.Signature{{Sig: base64.StdEncoding.EncodeToString(sig)}}})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"kind": "dsse", "apiVersion": "0.0.1",
		"spec": map[string]any{"proposedContent": map[string]any{"envelope": string(env), "verifiers": []string{base64.StdEncoding.EncodeToString(pub)}}}})
	if err != nil {
		t.Fatal(err)
	}
	// The request stays below the usual 32 MiB HTTP limit while its unbounded
	// index fan-out would previously occupy almost the entire shared queue.
	if len(body) >= 32<<20 {
		t.Fatal("invalid fan-out fixture")
	}
	return body
}
