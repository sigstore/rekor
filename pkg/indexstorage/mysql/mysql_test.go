// Copyright 2023 The Sigstore Authors.
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

package mysql

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sigstore/rekor/pkg/log"

	"go.uber.org/goleak"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/api/support/bundler"
)

// newMockDB returns a sqlx handle over a sqlmock connection. Mocks that expect writeStmt
// need QueryMatcherEqual, since its positional form contains "(?" and is not a valid regexp.
func newMockDB(t *testing.T, matcher sqlmock.QueryMatcher) (*sqlx.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(matcher))
	if err != nil {
		t.Fatalf("unexpected error creating mock db: %v", err)
	}
	return sqlx.NewDb(db, "mysql"), mock
}

// positionalWriteStmt renders writeStmt's named parameters in the positional form the driver
// actually receives.
func positionalWriteStmt() string {
	return regexp.MustCompile(`:[a-z]*`).ReplaceAllString(writeStmt, "?")
}

func TestLookupIndices(t *testing.T) {
	keys := []string{"87c1b129fbadd7b6e9abc0a9ef7695436d767aece042bec198a97e949fcbe14c"}
	value := []string{"1e1f2c881ae0608ec77ebf88a75c66d3099113a7343238f2f7a0ebb91a4ed335"}
	db, mock := newMockDB(t, sqlmock.QueryMatcherRegexp)

	isp := IndexStorageProvider{readDB: db}
	defer isp.Shutdown()

	mock.ExpectQuery(lookupStmt).WithArgs(keys[0]).WillReturnRows(sqlmock.NewRows(value))

	if _, err := isp.LookupIndices(context.Background(), keys); err != nil {
		t.Error(err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}

	expectedErr := errors.New("badness")
	mock.ExpectQuery(lookupStmt).WillReturnError(expectedErr)
	if _, err := isp.LookupIndices(context.Background(), keys); err == nil {
		t.Error("unexpected success")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestWriteIndex(t *testing.T) {
	keys := []string{"87c1b129fbadd7b6e9abc0a9ef7695436d767aece042bec198a97e949fcbe14c"}
	value := "1e1f2c881ae0608ec77ebf88a75c66d3099113a7343238f2f7a0ebb91a4ed335"
	db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)
	expectedStmt := positionalWriteStmt()

	isp := IndexStorageProvider{writeDB: db}
	defer isp.Shutdown()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations not met: %v", err)
	}

	mock.ExpectExec(expectedStmt).WithArgs(keys[0], value).WillReturnResult(sqlmock.NewResult(1, 1))
	if err := isp.WriteIndex(context.Background(), keys, value); err != nil {
		t.Errorf("%v, %v", expectedStmt, err)
	}
	isp.Flush()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}

	// keys queued together coalesce into a single wide INSERT
	keysBatch := []string{"key1", "key2"}
	valueBatch := "uuid1"
	expectedBatchStmt := expectedStmt + ",(?, ?)"
	mock.ExpectExec(expectedBatchStmt).WithArgs("key1", valueBatch, "key2", valueBatch).WillReturnResult(sqlmock.NewResult(2, 2))
	if err := isp.WriteIndex(context.Background(), keysBatch, valueBatch); err != nil {
		t.Errorf("%v, %v", expectedBatchStmt, err)
	}
	isp.Flush()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

// TestWriteIndexCoalescesAcrossCalls covers the point of the bundler: keys from separate
// entries, queued in separate WriteIndex calls, collapse into one INSERT. Batching within
// a single call was already what the pre-bundler multi-row insert did.
func TestWriteIndexCoalescesAcrossCalls(t *testing.T) {
	db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)
	// long enough that only the explicit Flush can close the bundle
	isp := IndexStorageProvider{writeDB: db, batchDelay: time.Minute}
	defer isp.Shutdown() //nolint:errcheck

	mock.ExpectExec(positionalWriteStmt()+",(?, ?)").
		WithArgs("key1", "uuid1", "key2", "uuid2").
		WillReturnResult(sqlmock.NewResult(2, 2))

	if err := isp.WriteIndex(context.Background(), []string{"key1"}, "uuid1"); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := isp.WriteIndex(context.Background(), []string{"key2"}, "uuid2"); err != nil {
		t.Fatalf("second write: %v", err)
	}
	isp.Flush()

	// a second INSERT here means the two calls did not share a bundle
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

// TestBatchDelayOption asserts the configured delay reaches the bundler, since nothing
// else observes it and an ignored value would silently keep the default.
func TestBatchDelayOption(t *testing.T) {
	for _, tc := range []struct{ delay, want time.Duration }{
		{0, bundleDelay},
		{time.Second, time.Second},
	} {
		t.Run(tc.delay.String(), func(t *testing.T) {
			db, _ := newMockDB(t, sqlmock.QueryMatcherEqual)
			isp := IndexStorageProvider{writeDB: db}
			WithBatchDelay(tc.delay).applyBatchDelay(&isp.batchDelay)
			t.Cleanup(func() { isp.Shutdown() }) //nolint:errcheck

			if got := isp.initBundler().DelayThreshold; got != tc.want {
				t.Errorf("got DelayThreshold = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestMaxEntryKeyCharsMatchesSchema keeps the guard pinned to the column it protects.
func TestMaxEntryKeyCharsMatchesSchema(t *testing.T) {
	want := fmt.Sprintf("varchar(%d)", maxEntryKeyChars)
	if !strings.Contains(createTableStmt, want) {
		t.Errorf("createTableStmt does not declare EntryKey as %s", want)
	}
}

// TestWriteIndexError covers the batch write exhausting its retries after WriteIndex has
// already returned nil, which is the only way a MySQL error can now surface.
func TestWriteIndexError(t *testing.T) {
	db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)

	// registered before the provider so Shutdown's drain still logs to the observer
	observed, logs := observer.New(zapcore.ErrorLevel)
	restore := log.Logger
	log.Logger = zap.New(observed).Sugar()
	defer func() { log.Logger = restore }()

	isp := IndexStorageProvider{writeDB: db}
	defer isp.Shutdown() //nolint:errcheck

	for range bundleWriteRetries + 1 {
		mock.ExpectExec(positionalWriteStmt()).WillReturnError(errors.New("badness"))
	}
	if err := isp.WriteIndex(context.Background(), []string{"key"}, "value"); err != nil {
		t.Errorf("queueing should not fail: %v", err)
	}
	isp.Flush()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
	// retries log at warn, below the observer's level, so only the final failure is seen
	if logs.FilterMessageSnippet("badness").Len() != 1 {
		t.Errorf("write failure was not logged exactly once, got entries: %v", logs.All())
	}
}

// TestWriteIndexRetry covers a transient failure: the bundle is retried and written, and
// nothing is reported as lost.
func TestWriteIndexRetry(t *testing.T) {
	db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)

	observed, logs := observer.New(zapcore.ErrorLevel)
	restore := log.Logger
	log.Logger = zap.New(observed).Sugar()
	defer func() { log.Logger = restore }()

	isp := IndexStorageProvider{writeDB: db}
	defer isp.Shutdown() //nolint:errcheck

	retriesBefore := testutil.ToFloat64(metricBatchWriteRetries)
	mock.ExpectExec(positionalWriteStmt()).WithArgs("key", "value").WillReturnError(errors.New("connection reset"))
	mock.ExpectExec(positionalWriteStmt()).WithArgs("key", "value").WillReturnResult(sqlmock.NewResult(1, 1))
	if err := isp.WriteIndex(context.Background(), []string{"key"}, "value"); err != nil {
		t.Errorf("queueing should not fail: %v", err)
	}
	isp.Flush()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
	if got := testutil.ToFloat64(metricBatchWriteRetries) - retriesBefore; got != 1 {
		t.Errorf("got %v retries, want 1", got)
	}
	if logs.Len() != 0 {
		t.Errorf("recovered write should not log an error, got entries: %v", logs.All())
	}
}

// TestWriteIndexKeepsEntryInOneBundle guards against an entry's keys being split across
// bundles, where one bundle could be written and the other lost. With a threshold of two
// items, per-key buffering would close the bundle partway through the second entry.
func TestWriteIndexKeepsEntryInOneBundle(t *testing.T) {
	db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)
	isp := IndexStorageProvider{writeDB: db, batchDelay: time.Minute}
	isp.initBundler().BundleCountThreshold = 2
	defer isp.Shutdown() //nolint:errcheck

	mock.ExpectExec(positionalWriteStmt()+",(?, ?),(?, ?)").
		WithArgs("a1", "uuidA", "b1", "uuidB", "b2", "uuidB").
		WillReturnResult(sqlmock.NewResult(3, 3))

	if err := isp.WriteIndex(context.Background(), []string{"a1"}, "uuidA"); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := isp.WriteIndex(context.Background(), []string{"b1", "b2"}, "uuidB"); err != nil {
		t.Fatalf("second write: %v", err)
	}
	isp.Flush()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

// TestWriteIndexOverflowIsAllOrNothing asserts a full buffer rejects an entry outright
// rather than buffering the keys that happen to fit.
func TestWriteIndexOverflowIsAllOrNothing(t *testing.T) {
	db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)
	isp := IndexStorageProvider{writeDB: db}
	// room for two of the three rows below; must be set before the first Add
	isp.initBundler().BufferedByteLimit = 2 * indexEntry{Key: "k1", UUID: "uuid"}.size()
	defer isp.Shutdown() //nolint:errcheck

	// with no expectation registered, any statement reaching the mock fails the test
	err := isp.WriteIndex(context.Background(), []string{"k1", "k2", "k3"}, "uuid")
	if !errors.Is(err, bundler.ErrOverflow) {
		t.Fatalf("got %v, want %v", err, bundler.ErrOverflow)
	}
	isp.Flush()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

// TestWriteIndexAfterShutdown asserts keys arriving once Shutdown has begun are rejected,
// since they would land in a bundle the drain never waits for.
func TestWriteIndexAfterShutdown(t *testing.T) {
	db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)
	mock.ExpectClose()
	isp := IndexStorageProvider{writeDB: db}
	if err := isp.Shutdown(); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	if err := isp.WriteIndex(context.Background(), []string{"key"}, "uuid"); !errors.Is(err, errShutdown) {
		t.Errorf("got %v, want %v", err, errShutdown)
	}
}

// TestExecBundleChunksRows asserts a bundle is split into INSERTs of at most
// maxRowsPerInsert rows, since an entry's key count is client controlled.
func TestExecBundleChunksRows(t *testing.T) {
	db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)
	isp := IndexStorageProvider{writeDB: db}
	defer isp.Shutdown() //nolint:errcheck

	keys := make([]string, maxRowsPerInsert+1)
	for i := range keys {
		keys[i] = fmt.Sprintf("key%04d", i)
	}
	mock.ExpectBegin()
	mock.ExpectExec(positionalWriteStmt() + strings.Repeat(",(?, ?)", maxRowsPerInsert-1)).
		WillReturnResult(sqlmock.NewResult(maxRowsPerInsert, maxRowsPerInsert))
	mock.ExpectExec(positionalWriteStmt()).WithArgs(keys[maxRowsPerInsert], "uuid").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	if err := isp.WriteIndex(context.Background(), keys, "uuid"); err != nil {
		t.Fatalf("write: %v", err)
	}
	isp.Flush()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

// TestExecBundleRollsBackChunks asserts that a later INSERT failure cannot leave an
// entry indexed under only the keys from an earlier chunk.
func TestExecBundleRollsBackChunks(t *testing.T) {
	db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)
	isp := IndexStorageProvider{writeDB: db}
	defer isp.Shutdown() //nolint:errcheck

	entries := make([]indexEntry, maxRowsPerInsert+1)
	for i := range entries {
		entries[i] = indexEntry{Key: fmt.Sprintf("key%04d", i), UUID: "uuid"}
	}
	mock.ExpectBegin()
	mock.ExpectExec(positionalWriteStmt() + strings.Repeat(",(?, ?)", maxRowsPerInsert-1)).
		WillReturnResult(sqlmock.NewResult(maxRowsPerInsert, maxRowsPerInsert))
	mock.ExpectExec(positionalWriteStmt()).WithArgs(entries[maxRowsPerInsert].Key, "uuid").
		WillReturnError(errors.New("write failed"))
	mock.ExpectRollback()

	if err := isp.execBundle(context.Background(), entries); err == nil {
		t.Fatal("expected chunk failure")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

// TestPoolSeparation asserts reads never touch the write pool and vice versa.
// Each mock fails the test if it receives an unexpected statement.
func TestPoolSeparation(t *testing.T) {
	keys := []string{"87c1b129fbadd7b6e9abc0a9ef7695436d767aece042bec198a97e949fcbe14c"}
	value := "1e1f2c881ae0608ec77ebf88a75c66d3099113a7343238f2f7a0ebb91a4ed335"

	readDB, readMock := newMockDB(t, sqlmock.QueryMatcherRegexp)
	writeDB, writeMock := newMockDB(t, sqlmock.QueryMatcherEqual)

	isp := IndexStorageProvider{readDB: readDB, writeDB: writeDB}
	defer isp.Shutdown()

	readMock.ExpectQuery(lookupStmt).WithArgs(keys[0]).
		WillReturnRows(sqlmock.NewRows([]string{"EntryUUID"}).AddRow(value))
	got, err := isp.LookupIndices(context.Background(), keys)
	if err != nil {
		t.Errorf("lookup: %v", err)
	}
	if len(got) != 1 || got[0] != value {
		t.Errorf("lookup returned %v, want [%s]", got, value)
	}

	writeMock.ExpectExec(positionalWriteStmt()).WithArgs(keys[0], value).WillReturnResult(sqlmock.NewResult(1, 1))
	if err := isp.WriteIndex(context.Background(), keys, value); err != nil {
		t.Errorf("write: %v", err)
	}
	isp.Flush()

	// an unmet expectation on either mock means a statement went to the wrong pool
	if err := readMock.ExpectationsWereMet(); err != nil {
		t.Errorf("read pool: %v", err)
	}
	if err := writeMock.ExpectationsWereMet(); err != nil {
		t.Errorf("write pool: %v", err)
	}
}

func TestDBStatsCollector(t *testing.T) {
	readDB, _ := newMockDB(t, sqlmock.QueryMatcherRegexp)
	writeDB, _ := newMockDB(t, sqlmock.QueryMatcherRegexp)
	isp := IndexStorageProvider{readDB: readDB, writeDB: writeDB}
	defer isp.Shutdown()

	collector := &dbStatsCollector{readDB: isp.readDB, writeDB: isp.writeDB}
	for _, name := range []string{
		"rekor_index_storage_db_connections_open",
		"rekor_index_storage_db_wait_count_total",
		"rekor_index_storage_db_wait_duration_seconds_total",
	} {
		if got := testutil.CollectAndCount(collector, name); got != 2 {
			t.Errorf("%s: got %d series, want 2 (one per pool)", name, got)
		}
	}

	problems, err := testutil.CollectAndLint(collector)
	if err != nil {
		t.Fatalf("lint: %v", err)
	}
	for _, p := range problems {
		t.Errorf("lint: %s: %s", p.Metric, p.Text)
	}
}

// TestDBStatsCollectorNilPool covers a partially constructed provider, where one pool was
// never opened.
func TestDBStatsCollectorNilPool(t *testing.T) {
	collector := &dbStatsCollector{}
	if got := testutil.CollectAndCount(collector); got != 0 {
		t.Errorf("got %d series from an empty collector, want 0", got)
	}
}

// TestShutdownUnregistersCollector guards against a closed provider holding the registry
// slot, which would report all-zero pool stats forever and block any replacement provider.
func TestShutdownUnregistersCollector(t *testing.T) {
	readDB, readMock := newMockDB(t, sqlmock.QueryMatcherRegexp)
	writeDB, writeMock := newMockDB(t, sqlmock.QueryMatcherRegexp)
	isp := IndexStorageProvider{readDB: readDB, writeDB: writeDB}
	isp.collector = &dbStatsCollector{readDB: isp.readDB, writeDB: isp.writeDB}

	if err := prometheus.DefaultRegisterer.Register(isp.collector); err != nil {
		t.Fatalf("register: %v", err)
	}
	readMock.ExpectClose()
	writeMock.ExpectClose()
	if err := isp.Shutdown(); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	for name, mock := range map[string]sqlmock.Sqlmock{"read": readMock, "write": writeMock} {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("%s pool not closed: %v", name, err)
		}
	}

	// the slot is free only if a replacement can claim it
	replacement := &dbStatsCollector{}
	if err := prometheus.DefaultRegisterer.Register(replacement); err != nil {
		t.Fatalf("registry slot still held after shutdown: %v", err)
	}
	prometheus.DefaultRegisterer.Unregister(replacement)
}

func TestConnOptionsAreRoleScoped(t *testing.T) {
	// each pool is opened with the full option slice, so an option meant for the other
	// pool must leave this one at its default of unlimited
	for _, tc := range []struct {
		name string
		opt  Options
		role poolRole
		want int
	}{
		{"read option on read pool", WithReadMaxOpenConns(5), poolRead, 5},
		{"read option on write pool", WithReadMaxOpenConns(5), poolWrite, 0},
		{"write option on write pool", WithWriteMaxOpenConns(7), poolWrite, 7},
		{"write option on read pool", WithWriteMaxOpenConns(7), poolRead, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, _ := newMockDB(t, sqlmock.QueryMatcherRegexp)
			defer db.Close()
			tc.opt.applyMaxOpenConns(db, tc.role)
			if got := db.Stats().MaxOpenConnections; got != tc.want {
				t.Errorf("got %d max open connections, want %d", got, tc.want)
			}
		})
	}
}

func TestUninitializedClient(t *testing.T) {
	// this is not initialized with a real mysql client
	isp := IndexStorageProvider{}
	if _, err := isp.LookupIndices(context.Background(), []string{"key"}); err == nil {
		t.Error("unexpected success")
	}
	if err := isp.WriteIndex(context.Background(), []string{"key"}, "value"); err == nil {
		t.Error("unexpected success")
	}
}

// TestWriteIndexKeyLengthLimit pins the skip to EntryKey's character limit rather than its
// byte length: utf8mb4 permits four bytes per character, so a 512 character key of astral
// codepoints is 2048 bytes and still fits the column.
func TestWriteIndexKeyLengthLimit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		key     string
		skipped bool
	}{
		{"ascii at limit", strings.Repeat("a", maxEntryKeyChars), false},
		{"ascii over limit", strings.Repeat("a", maxEntryKeyChars+1), true},
		{"four byte runes at limit", strings.Repeat("𝔘", maxEntryKeyChars), false},
		{"four byte runes over limit", strings.Repeat("𝔘", maxEntryKeyChars+1), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)
			isp := IndexStorageProvider{writeDB: db}
			t.Cleanup(func() { isp.Shutdown() }) //nolint:errcheck

			// with no expectation registered, any statement reaching the mock fails the test
			if !tc.skipped {
				mock.ExpectExec(positionalWriteStmt()).WithArgs(tc.key, "uuid").
					WillReturnResult(sqlmock.NewResult(1, 1))
			}
			if err := isp.WriteIndex(context.Background(), []string{tc.key}, "uuid"); err != nil {
				t.Fatalf("write: %v", err)
			}
			isp.Flush()

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Error(err)
			}
		})
	}
}

// TestWriteIndexSkipsOnlyOversizedKey guards the per-key granularity of the skip: dropping
// one key must not cost the entry its remaining, valid index keys.
func TestWriteIndexSkipsOnlyOversizedKey(t *testing.T) {
	db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)
	isp := IndexStorageProvider{writeDB: db}
	defer isp.Shutdown() //nolint:errcheck

	oversized := strings.Repeat("a", maxEntryKeyChars+1)
	mock.ExpectExec(positionalWriteStmt()+",(?, ?)").WithArgs("good1", "uuid", "good2", "uuid").
		WillReturnResult(sqlmock.NewResult(2, 2))

	if err := isp.WriteIndex(context.Background(), []string{"good1", oversized, "good2"}, "uuid"); err != nil {
		t.Fatalf("write: %v", err)
	}
	isp.Flush()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

// TestBundlerHandlerLimit pins how HandlerLimit is derived from the write pool: it tracks
// the pool's limit so batch writers cannot outnumber the connections they need, and an
// unlimited pool falls back to defaultHandlerLimit rather than the bundler's default of 1.
func TestBundlerHandlerLimit(t *testing.T) {
	for _, tc := range []struct{ writeMaxOpen, want int }{
		{1, 1},
		{5, 5},
		{20, 20},
		{0, defaultHandlerLimit},
	} {
		t.Run(fmt.Sprintf("max_open_conns_%d", tc.writeMaxOpen), func(t *testing.T) {
			writeDB, _ := newMockDB(t, sqlmock.QueryMatcherEqual)
			writeDB.SetMaxOpenConns(tc.writeMaxOpen)
			isp := IndexStorageProvider{writeDB: writeDB}
			t.Cleanup(func() { isp.Shutdown() }) //nolint:errcheck

			if got := isp.initBundler().HandlerLimit; got != tc.want {
				t.Errorf("got bundler.HandlerLimit = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// Shutdown must cancel a blocked write and skip queued SQL when its drain expires.
func TestShutdownCancelsOutstandingBundles(t *testing.T) {
	db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)
	db.SetMaxOpenConns(1)
	isp := IndexStorageProvider{writeDB: db, batchDelay: time.Hour}
	isp.initBundler().BundleCountThreshold = 1
	mock.ExpectExec(positionalWriteStmt()).WillDelayFor(time.Hour).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectClose()
	for i := range 3 {
		if err := isp.WriteIndex(context.Background(), []string{"key"}, fmt.Sprint(i)); err != nil {
			t.Fatal(err)
		}
	}
	// Wait until the first SQL call is in flight before expiring the drain.
	deadline := time.Now().Add(time.Second)
	for db.Stats().InUse == 0 {
		if time.Now().After(deadline) {
			t.Fatal("batch did not start")
		}
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if err := isp.shutdown(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("shutdown: got %v, want canceled drain", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("shutdown did not cancel the in-flight write promptly")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
	if err := isp.WriteIndex(context.Background(), []string{"late"}, "uuid"); !errors.Is(err, errShutdown) {
		t.Fatalf("late write: %v", err)
	}
}

func TestConcurrentShutdownDrainsAndPreservesError(t *testing.T) {
	db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)
	isp := IndexStorageProvider{writeDB: db, batchDelay: time.Hour}
	mock.ExpectExec(positionalWriteStmt()).WithArgs("key", "uuid").
		WillReturnResult(sqlmock.NewResult(1, 1))
	closeErr := errors.New("close failed")
	mock.ExpectClose().WillReturnError(closeErr)
	if err := isp.WriteIndex(context.Background(), []string{"key"}, "uuid"); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 8)
	for range cap(results) {
		go func() { results <- isp.Shutdown() }()
	}
	for range cap(results) {
		if err := <-results; !errors.Is(err, closeErr) {
			t.Fatalf("shutdown lost close error: %v", err)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenPoolHonorsStartupCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	db, err := openPool(ctx, "user@tcp(127.0.0.1:3306)/test", poolRead, nil)
	if !errors.Is(err, context.Canceled) || db != nil {
		t.Fatalf("got (%v, %v), want nil pool and context cancellation", db, err)
	}
}

func TestShutdownBoundedWhenHandlerIgnoresCancellation(t *testing.T) {
	db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)
	mock.ExpectClose()
	p := &IndexStorageProvider{writeDB: db}
	p.initBundler()
	release := make(chan struct{})
	started := make(chan struct{})
	p.bundler = bundler.NewBundler(0, func(any) { close(started); <-release })
	p.bundler.BundleCountThreshold = 1
	if err := p.bundler.Add(1, 1); err != nil {
		t.Fatal(err)
	}
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	err := p.shutdown(ctx)
	close(release)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("shutdown: %v", err)
	}
	if time.Since(start) > shutdownCancelGrace+time.Second {
		t.Fatal("shutdown wait is unbounded")
	}
	deadline := time.Now().Add(time.Second)
	for db.Stats().OpenConnections != 0 {
		if time.Now().After(deadline) {
			t.Fatal("deferred cleanup did not close pool")
		}
		time.Sleep(time.Millisecond)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestWriteIndexRejectsExcessiveFanoutBeforeBuffering(t *testing.T) {
	for _, tc := range []struct {
		name  string
		count int
		wide  bool
	}{
		{"keys_over_limit", maxIndexKeysPerEntry + 1, false},
		{"quarter_million_keys", 250000, false},
		{"larger_than_buffer", 280000, false},
		{"bytes_over_limit", maxIndexKeysPerEntry, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)
			p := IndexStorageProvider{writeDB: db, batchDelay: time.Hour}
			defer p.Shutdown() //nolint:errcheck
			keys := make([]string, tc.count)
			for i := range keys {
				keys[i] = fmt.Sprintf("%06d:0", i)
				if tc.wide {
					keys[i] += strings.Repeat("界", 500)
				}
			}
			oversized := testutil.ToFloat64(metricRejectedEntries.WithLabelValues("oversized"))
			overflow := testutil.ToFloat64(metricRejectedEntries.WithLabelValues("overflow"))
			pending := testutil.ToFloat64(metricPendingBytes)
			failed := testutil.ToFloat64(metricBatchWrites.WithLabelValues("false"))
			if err := p.WriteIndex(context.Background(), keys, strings.Repeat("a", 80)); !errors.Is(err, bundler.ErrOversizedItem) {
				t.Fatalf("got %v, want oversized entry", err)
			}
			if testutil.ToFloat64(metricRejectedEntries.WithLabelValues("oversized")) != oversized+1 ||
				testutil.ToFloat64(metricRejectedEntries.WithLabelValues("overflow")) != overflow ||
				testutil.ToFloat64(metricPendingBytes) != pending {
				t.Fatal("oversized entry consumed queue capacity or was classified as overflow")
			}
			// A subsequent ordinary upload must still reach SQL, without any of the
			// rejected entry's keys or a retry loop from the rejected entry.
			mock.ExpectExec(positionalWriteStmt()).WithArgs("healthy", "uuid").WillReturnResult(sqlmock.NewResult(1, 1))
			if err := p.WriteIndex(context.Background(), []string{"healthy"}, "uuid"); err != nil {
				t.Fatal(err)
			}
			p.Flush()
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
			if testutil.ToFloat64(metricBatchWrites.WithLabelValues("false")) != failed {
				t.Fatal("rejected entry reached batch handler")
			}
		})
	}
}

func TestWriteIndexDeduplicatesBeforeLimits(t *testing.T) {
	db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)
	p := IndexStorageProvider{writeDB: db, batchDelay: time.Hour}
	defer p.Shutdown() //nolint:errcheck
	keys := make([]string, 250000)
	for i := range keys {
		keys[i] = "duplicate"
	}
	mock.ExpectExec(positionalWriteStmt()+",(?, ?)").WithArgs("duplicate", "first", "duplicate", "second").WillReturnResult(sqlmock.NewResult(2, 2))
	before := testutil.ToFloat64(metricPendingBytes)
	if err := p.WriteIndex(context.Background(), keys, "first"); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(metricPendingBytes) - before; got != float64((indexEntry{Key: "duplicate", UUID: "first"}).size()) {
		t.Fatalf("charged %v bytes for one unique row", got)
	}
	if err := p.WriteIndex(context.Background(), keys, "second"); err != nil {
		t.Fatal(err)
	}
	p.Flush()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestBusyBundlerTailCannotExceedByteLimit(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	statement := func(n int) string { return positionalWriteStmt() + strings.Repeat(",(?, ?)", n-1) }
	first := statement(bundleCount)
	matcher := sqlmock.QueryMatcherFunc(func(expected, actual string) error {
		if expected != actual {
			return fmt.Errorf("unexpected SQL statement: got %d rows, expected %d", strings.Count(actual, "(?, ?)"), strings.Count(expected, "(?, ?)"))
		}
		if expected == first {
			close(started)
			<-release
		}
		return nil
	})
	db, mock := newMockDB(t, matcher)
	db.SetMaxOpenConns(1)
	p := IndexStorageProvider{writeDB: db, batchDelay: time.Hour}
	defer p.Shutdown() //nolint:errcheck
	b := p.initBundler()
	if b.BundleByteLimit != bundleByteLimit || b.BundleByteThreshold != bundleByteLimit {
		t.Fatal("missing explicit byte bounds")
	}
	mock.ExpectExec(first).WillReturnResult(sqlmock.NewResult(0, bundleCount))
	// Each wide entry accounts for 217088 bytes. Only four fit in a 1 MiB
	// bundle, even while the sole handler is blocked and tails coalesce.
	for range 5 {
		mock.ExpectBegin()
		for range 4 {
			mock.ExpectExec(statement(maxRowsPerInsert)).WillReturnResult(sqlmock.NewResult(0, maxRowsPerInsert))
		}
		mock.ExpectExec(statement(96)).WillReturnResult(sqlmock.NewResult(0, 96))
		mock.ExpectCommit()
	}
	for i := range bundleCount {
		if err := p.WriteIndex(context.Background(), []string{"initial"}, fmt.Sprintf("%080d", i)); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("handler never started")
	}
	keys := make([]string, 1024)
	for i := range keys {
		keys[i] = fmt.Sprintf("%04d", i) + strings.Repeat("x", 96)
	}
	for i := range 20 {
		if err := p.WriteIndex(context.Background(), keys, fmt.Sprintf("%080d", i)); err != nil {
			t.Fatal(err)
		}
	}
	close(release)
	p.Flush()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestWriteIndexByteLimitBoundary(t *testing.T) {
	db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)
	p := IndexStorageProvider{writeDB: db, batchDelay: time.Hour}
	defer p.Shutdown() //nolint:errcheck
	id := strings.Repeat("a", 80)
	keys := make([]string, 1024)
	for i := range keys {
		// 912 UTF-8 bytes plus the 80-byte ID and 32-byte headers = 1024.
		keys[i] = fmt.Sprintf("%012d", i) + strings.Repeat("界", 300)
	}
	mock.ExpectBegin()
	mock.ExpectExec(positionalWriteStmt() + strings.Repeat(",(?, ?)", 999)).WillReturnResult(sqlmock.NewResult(0, 1000))
	mock.ExpectExec(positionalWriteStmt() + strings.Repeat(",(?, ?)", 23)).WillReturnResult(sqlmock.NewResult(0, 24))
	mock.ExpectCommit()
	if err := p.WriteIndex(context.Background(), keys, id); err != nil {
		t.Fatalf("entry at the byte limit was rejected: %v", err)
	}
	p.Flush()
	keys[0] += "x"
	if err := p.WriteIndex(context.Background(), keys, id); !errors.Is(err, bundler.ErrOversizedItem) {
		t.Fatalf("entry one byte above the limit: %v", err)
	}
	p.Flush()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestWriteIndexUTF8Validation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		key   string
		valid bool
	}{
		{"invalid_byte", "prefix\xffsuffix", false},
		{"truncated_sequence", "\xe2\x82", false},
		{"surrogate", "\xed\xa0\x80", false},
		{"overlong_encoding", "\xc0\xaf", false},
		{"valid_replacement_character", "\ufffd", true},
		{"valid_four_byte_character", "\U0001f600", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)
			p := IndexStorageProvider{writeDB: db, batchDelay: time.Hour}
			defer p.Shutdown() //nolint:errcheck
			invalidBefore := testutil.ToFloat64(metricInvalidUTF8Keys)
			oversizedBefore := testutil.ToFloat64(metricSkippedKeys)
			pendingBefore := testutil.ToFloat64(metricPendingBytes)
			wantBytes := (indexEntry{Key: "before", UUID: "uuid"}).size() + (indexEntry{Key: "after", UUID: "uuid"}).size()
			if tc.valid {
				mock.ExpectExec(positionalWriteStmt()+",(?, ?),(?, ?)").
					WithArgs("after", "uuid", "before", "uuid", tc.key, "uuid").
					WillReturnResult(sqlmock.NewResult(0, 3))
				wantBytes += (indexEntry{Key: tc.key, UUID: "uuid"}).size()
			} else {
				mock.ExpectExec(positionalWriteStmt()+",(?, ?)").
					WithArgs("after", "uuid", "before", "uuid").
					WillReturnResult(sqlmock.NewResult(0, 2))
			}
			if err := p.WriteIndex(context.Background(), []string{"before", tc.key, "after"}, "uuid"); err != nil {
				t.Fatal(err)
			}
			if got := testutil.ToFloat64(metricPendingBytes) - pendingBefore; got != float64(wantBytes) {
				t.Fatalf("accounted bytes: got %v, want %d", got, wantBytes)
			}
			wantInvalid := invalidBefore
			if !tc.valid {
				wantInvalid++
			}
			if testutil.ToFloat64(metricInvalidUTF8Keys) != wantInvalid || testutil.ToFloat64(metricSkippedKeys) != oversizedBefore {
				t.Fatal("invalid UTF-8 was not counted separately from oversized keys")
			}
			p.Flush()
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWriteIndexSummarizesSkippedKeys(t *testing.T) {
	for _, mode := range []string{"repeated", "varying_lengths", "invalid_utf8", "mixed", "all_skipped", "early_rejection", "valid_only"} {
		t.Run(mode, func(t *testing.T) {
			core, observed := observer.New(zap.WarnLevel) // Unsampled: enforce the bound even in dev mode.
			previousLogger := log.Logger
			log.Logger = zap.New(core).Sugar()
			t.Cleanup(func() { log.Logger = previousLogger })
			db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)
			p := IndexStorageProvider{writeDB: db, batchDelay: time.Hour}
			defer p.Shutdown() //nolint:errcheck
			invalidBefore := testutil.ToFloat64(metricInvalidUTF8Keys)
			oversizedBefore := testutil.ToFloat64(metricSkippedKeys)
			pendingBefore := testutil.ToFloat64(metricPendingBytes)
			keys := []string{"valid", "valid"}
			if mode == "all_skipped" {
				keys = nil
			}
			invalid, oversized := 0, 0
			longKeys := make([]string, 64)
			for i := range longKeys {
				longKeys[i] = strings.Repeat("x", maxEntryKeyChars+1+i)
			}
			switch mode {
			case "early_rejection":
				keys = append(keys, "\xff", longKeys[0])
				invalid, oversized = 1, 1
				for i := range maxIndexKeysPerEntry {
					keys = append(keys, fmt.Sprintf("unique-%d", i))
				}
			case "valid_only":
			default:
				for i := range 200000 {
					switch {
					case mode == "invalid_utf8" || mode == "mixed" && i%2 == 0:
						keys = append(keys, "\xff")
						invalid++
					case mode == "repeated":
						keys = append(keys, longKeys[0])
						oversized++
					default:
						keys = append(keys, longKeys[i%len(longKeys)])
						oversized++
					}
				}
			}
			if mode != "early_rejection" && mode != "all_skipped" {
				mock.ExpectExec(positionalWriteStmt()).WithArgs("valid", "uuid").WillReturnResult(sqlmock.NewResult(0, 1))
			}
			err := p.WriteIndex(context.Background(), keys, "uuid")
			if mode == "early_rejection" {
				if !errors.Is(err, bundler.ErrOversizedItem) {
					t.Fatalf("got %v, want oversized rejection", err)
				}
				if testutil.ToFloat64(metricPendingBytes) != pendingBefore {
					t.Fatal("rejected entry consumed buffer capacity")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			p.Flush()
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
			if testutil.ToFloat64(metricInvalidUTF8Keys)-invalidBefore != float64(invalid) ||
				testutil.ToFloat64(metricSkippedKeys)-oversizedBefore != float64(oversized) {
				t.Fatal("summary counters lost skipped occurrences")
			}
			logs := observed.All()
			if mode == "valid_only" {
				if len(logs) != 0 {
					t.Fatalf("unexpected warnings: %v", logs)
				}
				return
			}
			if len(logs) != 1 || logs[0].Message != "skipping invalid search index keys" {
				t.Fatalf("got %d logs, want one fixed-message summary", len(logs))
			}
			fields := logs[0].ContextMap()
			if fields["entry_id"] != "uuid" || fields["invalid_utf8_keys"] != int64(invalid) || fields["oversized_keys"] != int64(oversized) {
				t.Fatalf("incorrect summary fields: %v", fields)
			}
		})
	}
}

func TestWriteIndexLargeEntriesPreserveAllKeys(t *testing.T) {
	for _, tc := range []struct {
		name   string
		count  int
		format string
	}{
		{"provenance_digests", 1500, "sha256:%064x"},
		{"key_limit", maxIndexKeysPerEntry, "%04x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)
			p := IndexStorageProvider{writeDB: db, batchDelay: time.Hour}
			defer p.Shutdown() //nolint:errcheck
			id := strings.Repeat("a", 80)
			keys := make([]string, tc.count)
			mock.ExpectBegin()
			for start := 0; start < len(keys); start += maxRowsPerInsert {
				end := min(start+maxRowsPerInsert, len(keys))
				args := make([]driver.Value, 0, 2*(end-start))
				for i := start; i < end; i++ {
					keys[i] = fmt.Sprintf(tc.format, i)
					args = append(args, keys[i], id)
				}
				mock.ExpectExec(positionalWriteStmt() + strings.Repeat(",(?, ?)", end-start-1)).
					WithArgs(args...).WillReturnResult(sqlmock.NewResult(0, int64(end-start)))
			}
			mock.ExpectCommit()
			if err := p.WriteIndex(context.Background(), keys, id); err != nil {
				t.Fatal(err)
			}
			p.Flush()
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Test actual SQL order across entry boundaries, chunk boundaries, and a retry.
func TestWriteBundleOrdersWholeTransaction(t *testing.T) {
	db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)
	p := IndexStorageProvider{writeDB: db, batchDelay: time.Hour}
	defer p.Shutdown() //nolint:errcheck
	var want []indexEntry
	for i := 0; i < 501; i++ {
		key := fmt.Sprintf("key%04d", i)
		want = append(want, indexEntry{Key: strings.ToUpper(key), UUID: "a"},
			indexEntry{Key: key, UUID: "b"})
	}
	for attempt := 0; attempt < 2; attempt++ {
		mock.ExpectBegin()
		for offset := 0; offset < len(want); offset += maxRowsPerInsert {
			end := min(offset+maxRowsPerInsert, len(want))
			args := make([]driver.Value, 0, 2*(end-offset))
			for _, row := range want[offset:end] {
				args = append(args, row.Key, row.UUID)
			}
			expect := mock.ExpectExec(positionalWriteStmt() + strings.Repeat(",(?, ?)", end-offset-1)).WithArgs(args...)
			if attempt == 0 && offset > 0 {
				expect.WillReturnError(errors.New("deadlock"))
			} else {
				expect.WillReturnResult(sqlmock.NewResult(0, int64(end-offset)))
			}
		}
		if attempt == 0 {
			mock.ExpectRollback()
		} else {
			mock.ExpectCommit()
		}
	}
	// Reverse both key order and entry order; sorting only each individual entry
	// would still acquire locks in the wrong order.
	for _, uuid := range []string{"b", "a"} {
		var keys []string
		for i := 500; i >= 0; i-- {
			key := fmt.Sprintf("key%04d", i)
			if uuid == "a" {
				key = strings.ToUpper(key)
			}
			keys = append(keys, key)
		}
		if err := p.WriteIndex(context.Background(), keys, uuid); err != nil {
			t.Fatal(err)
		}
	}
	p.Flush()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
