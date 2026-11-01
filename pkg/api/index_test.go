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

package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sigstore/rekor/pkg/events"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/index"
	"github.com/sigstore/rekor/pkg/indexstorage"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/types"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/api/support/bundler"
)

func Test_Collection(t *testing.T) {

	vals := []string{"foo", "bar", "baz", "baz", "baz"}

	t.Run("Unique", func(t *testing.T) {
		unq := NewUniq()
		unq.Add(vals...)

		if len(unq.Values()) != 3 {
			t.Errorf("expected 3 unique values, got %d", len(unq.Values()))
		}
		expected := []string{"foo", "bar", "baz"}
		if !testEqualNoOrder(t, expected, unq.Values()) {
			t.Errorf("expected %v, got %v", expected, unq.Values())
		}
	})

	t.Run("Collection", func(t *testing.T) {

		uniq1 := []string{"foo", "bar", "baz"}
		uniq2 := []string{"foo", "bar", "baz"}
		uniq3 := []string{"corge", "grault", "garply", "foo"}

		tests := []struct {
			name     string
			operator string
			expected []string
		}{
			{name: "with 'and' operator",
				operator: "and",
				expected: []string{"foo"},
			},
			{name: "with 'or' operator",
				operator: "or",
				expected: []string{"foo", "bar", "baz", "corge", "grault", "garply"},
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				c := NewCollection(test.operator)
				c.Add(uniq1)
				c.Add(uniq2)
				c.Add(uniq3)

				if !testEqualNoOrder(t, test.expected, c.Values()) {
					t.Errorf("expected %v, got %v", test.expected, c.Values())
				}
			})
		}

	})

}

// testEqualNoOrder compares two slices of strings without considering order.
func testEqualNoOrder(t *testing.T, expected, actual []string) bool {
	t.Helper()
	less := func(a, b string) bool { return a < b }
	return cmp.Diff(actual, expected, cmpopts.SortSlices(less)) == ""
}

type fakeIndexStorage struct {
	keyToUUIDs map[string][]string
	lookups    [][]string
	err        error
	shutdown   func()
}

func (f *fakeIndexStorage) LookupIndices(_ context.Context, keys []string) ([]string, error) {
	captured := make([]string, len(keys))
	copy(captured, keys)
	f.lookups = append(f.lookups, captured)
	if f.err != nil {
		return nil, f.err
	}
	var out []string
	for _, k := range keys {
		out = append(out, f.keyToUUIDs[k]...)
	}
	return out, nil
}

func (f *fakeIndexStorage) WriteIndex(_ context.Context, _ []string, _ string) error {
	return f.err
}

func (f *fakeIndexStorage) Shutdown() error {
	if f.shutdown != nil {
		f.shutdown()
	}
	return nil
}

func swapIndexStorage(t *testing.T, replacement indexstorage.IndexStorage) {
	t.Helper()
	prev := indexStorageClient
	indexStorageClient = replacement
	t.Cleanup(func() { indexStorageClient = prev })
}

func TestStopAPIWaitsForIndexWriters(t *testing.T) {
	t.Cleanup(func() { indexStorageStopped = false })
	previousAPI := api
	api = &API{}
	t.Cleanup(func() { api = previousAPI })

	shutdownCalled := make(chan struct{})
	swapIndexStorage(t, &fakeIndexStorage{shutdown: func() { close(shutdownCalled) }})

	indexStorageWriters.Add(1)
	writerReleased := false
	defer func() {
		if !writerReleased {
			indexStorageWriters.Done()
		}
	}()
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		StopAPI()
	}()

	select {
	case <-shutdownCalled:
		t.Fatal("index storage shut down before its producer completed")
	case <-time.After(25 * time.Millisecond):
	}

	indexStorageWriters.Done()
	writerReleased = true
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("StopAPI did not continue after its index producer completed")
	}
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

func TestSearchIndexHandler_SubjectStorageError(t *testing.T) {
	const sanURI = "https://github.com/o/r/.github/workflows/x.yml@refs/heads/main"
	fake := &fakeIndexStorage{err: errors.New("boom")}
	swapIndexStorage(t, fake)

	// "and" forces an immediate lookup so the storage error surfaces.
	resp := SearchIndexHandler(newSearchParams(t, models.SearchIndex{
		Subject:  sanURI,
		Operator: "and",
	}))

	rec := httptest.NewRecorder()
	resp.WriteResponse(rec, runtime.JSONProducer())
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, rec.Code)
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

// Embedding leaves irrelevant entry operations unimplemented; indexing must only
// inspect keys, never alter the accepted log entry or its response.
type acceptedIndexEntry struct{ types.EntryImpl }

func (acceptedIndexEntry) IndexKeys() ([]string, error) { return []string{"key"}, nil }

func TestIndexAcceptedEntryFailsOpen(t *testing.T) {
	for _, failure := range []error{bundler.ErrOverflow, bundler.ErrOversizedItem} {
		t.Run(failure.Error(), func(t *testing.T) {
			swapIndexStorage(t, &fakeIndexStorage{err: failure})
			core, observed := observer.New(zap.ErrorLevel)
			previousLogger := log.Logger
			log.Logger = zap.New(core).Sugar()
			t.Cleanup(func() { log.Logger = previousLogger })
			// This call deliberately has no error or responder return: indexing cannot
			// override the upload response, even when enqueueing fails.
			indexAcceptedEntry(context.Background(), acceptedIndexEntry{}, "uuid")
			indexStorageWriters.Wait()
			if observed.FilterMessageSnippet(failure.Error()).Len() != 1 {
				t.Fatalf("enqueue failure was not reported: %v", observed.All())
			}
		})
	}
}

type stalledClosePublisher struct {
	closing chan struct{}
	release chan struct{}
}

func (*stalledClosePublisher) Publish(context.Context, *events.Event, events.EventContentType) error {
	return nil
}

func (p *stalledClosePublisher) Close() error {
	close(p.closing)
	<-p.release
	return nil
}

func TestStopAPIDrainsIndexBeforePublisherClose(t *testing.T) {
	previousAPI, previousStopped := api, indexStorageStopped
	t.Cleanup(func() {
		api, indexStorageStopped = previousAPI, previousStopped
	})
	publisher := &stalledClosePublisher{closing: make(chan struct{}), release: make(chan struct{})}
	api = &API{newEntryPublisher: publisher}
	indexDrained := make(chan struct{})
	swapIndexStorage(t, &fakeIndexStorage{shutdown: func() { close(indexDrained) }})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		StopAPI()
	}()
	defer func() {
		close(publisher.release)
		select {
		case <-stopped:
		case <-time.After(time.Second):
			t.Error("StopAPI did not finish after releasing publisher")
		}
	}()
	select {
	case <-publisher.closing:
	case <-time.After(time.Second):
		t.Fatal("publisher close was not reached")
	}
	select {
	case <-indexDrained:
	default:
		t.Fatal("publisher close blocked before index drain")
	}
	select {
	case <-stopped:
		t.Fatal("StopAPI returned before publisher close completed")
	default:
	}
}
