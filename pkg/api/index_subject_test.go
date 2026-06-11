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
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/go-openapi/runtime/middleware"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/index"
)

type fakeIndexStorage struct {
	keyToUUIDs map[string][]string
	lookups    [][]string
}

func (f *fakeIndexStorage) LookupIndices(_ context.Context, keys []string) ([]string, error) {
	captured := make([]string, len(keys))
	copy(captured, keys)
	f.lookups = append(f.lookups, captured)
	var out []string
	for _, k := range keys {
		out = append(out, f.keyToUUIDs[k]...)
	}
	return out, nil
}

func (f *fakeIndexStorage) WriteIndex(_ context.Context, _ []string, _ string) error {
	return nil
}

func (f *fakeIndexStorage) Shutdown() error { return nil }

func swapIndexStorage(t *testing.T, fake *fakeIndexStorage) {
	t.Helper()
	prev := indexStorageClient
	indexStorageClient = fake
	t.Cleanup(func() { indexStorageClient = prev })
}

func newSearchParams(t *testing.T, q models.SearchIndex) index.SearchIndexParams {
	t.Helper()
	p := index.NewSearchIndexParams()
	p.HTTPRequest = httptest.NewRequest(http.MethodPost, "/api/v1/index/retrieve", nil)
	p.Query = &q
	return p
}

func okPayload(t *testing.T, r middleware.Responder) []string {
	t.Helper()
	ok, isOK := r.(*index.SearchIndexOK)
	if !isOK {
		t.Fatalf("expected *index.SearchIndexOK, got %T", r)
	}
	out := append([]string(nil), ok.Payload...)
	sort.Strings(out)
	return out
}

func TestSearchIndexHandler_SubjectOnly(t *testing.T) {
	const sanURI = "https://github.com/sofico-codebase/.github/.github/workflows/fabric-build.yaml@refs/heads/main"
	fake := &fakeIndexStorage{keyToUUIDs: map[string][]string{
		sanURI: {"uuid-1", "uuid-2"},
	}}
	swapIndexStorage(t, fake)

	resp := SearchIndexHandler(newSearchParams(t, models.SearchIndex{Subject: sanURI}))

	got := okPayload(t, resp)
	want := []string{"uuid-1", "uuid-2"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("payload: want %v, got %v", want, got)
	}
	if len(fake.lookups) != 1 || len(fake.lookups[0]) != 1 || fake.lookups[0][0] != sanURI {
		t.Fatalf("expected LookupIndices([%q]); got %v", sanURI, fake.lookups)
	}
}

func TestSearchIndexHandler_SubjectLowercased(t *testing.T) {
	// indexstorage canonicalizes to lowercase; handler must match.
	const mixed = "https://GitHub.com/OwnerName/RepoName/.github/workflows/Build.yml@refs/heads/Main"
	const lower = "https://github.com/ownername/reponame/.github/workflows/build.yml@refs/heads/main"
	fake := &fakeIndexStorage{}
	swapIndexStorage(t, fake)

	_ = SearchIndexHandler(newSearchParams(t, models.SearchIndex{Subject: mixed}))

	if len(fake.lookups) != 1 || fake.lookups[0][0] != lower {
		t.Fatalf("expected lowercased lookup %q; got %v", lower, fake.lookups)
	}
}

func TestSearchIndexHandler_SubjectAndShaAndOperator(t *testing.T) {
	const sanURI = "https://github.com/o/r/.github/workflows/x.yml@refs/heads/main"
	const sha = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	fake := &fakeIndexStorage{keyToUUIDs: map[string][]string{
		sanURI: {"shared", "subject-only"},
		sha:    {"shared", "sha-only"},
	}}
	swapIndexStorage(t, fake)

	resp := SearchIndexHandler(newSearchParams(t, models.SearchIndex{
		Subject:  sanURI,
		Hash:     sha,
		Operator: "and",
	}))

	got := okPayload(t, resp)
	if len(got) != 1 || got[0] != "shared" {
		t.Fatalf("AND intersection: want [shared], got %v", got)
	}
}

func TestSearchIndexHandler_SubjectAndShaOrOperator(t *testing.T) {
	const sanURI = "https://github.com/o/r/.github/workflows/x.yml@refs/heads/main"
	const sha = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	fake := &fakeIndexStorage{keyToUUIDs: map[string][]string{
		sanURI: {"subject-only", "shared"},
		sha:    {"sha-only", "shared"},
	}}
	swapIndexStorage(t, fake)

	resp := SearchIndexHandler(newSearchParams(t, models.SearchIndex{
		Subject:  sanURI,
		Hash:     sha,
		Operator: "or",
	}))

	got := okPayload(t, resp)
	want := []string{"sha-only", "shared", "subject-only"}
	if len(got) != len(want) {
		t.Fatalf("OR union: want %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("OR union: want %v, got %v", want, got)
		}
	}
}
