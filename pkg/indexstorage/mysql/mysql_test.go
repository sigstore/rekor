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
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"go.uber.org/goleak"
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

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}

	expectedErr := errors.New("badness")
	mock.ExpectExec(expectedStmt).WillReturnError(expectedErr)
	if err := isp.WriteIndex(context.Background(), keys, value); err == nil {
		t.Error("unexpected success")
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

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
