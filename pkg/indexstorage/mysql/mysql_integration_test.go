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

package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/api/support/bundler"
)

// This DSN must point to a disposable database: tests replace EntryIndex contents.
func integrationProvider(t *testing.T) (*IndexStorageProvider, *sqlx.DB) {
	t.Helper()
	dsn := os.Getenv("REKOR_INDEX_TEST_DSN")
	if dsn == "" {
		t.Skip("set REKOR_INDEX_TEST_DSN to a disposable MySQL database")
	}
	p, err := NewProvider(dsn, WithWriteMaxOpenConns(1), WithBatchDelay(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Shutdown() })
	db, err := sqlx.Connect("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec("DELETE FROM EntryIndex"); err != nil {
		t.Fatal(err)
	}
	return p, db
}

func lockIndex(t *testing.T, db *sqlx.DB) func() {
	t.Helper()
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), "LOCK TABLES EntryIndex WRITE"); err != nil {
		t.Fatal(err)
	}
	unlock := func() { _, _ = conn.ExecContext(context.Background(), "UNLOCK TABLES"); _ = conn.Close() }
	t.Cleanup(unlock)
	return unlock
}

func await(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestMySQLBlockedBufferAndShutdown(t *testing.T) {
	p, db := integrationProvider(t)
	unlock := lockIndex(t, db)
	b := p.initBundler()
	b.BufferedByteLimit = 16 << 10
	b.BundleCountThreshold = 1
	beforeGoroutines := runtime.NumGoroutine()
	pendingBefore := testutil.ToFloat64(metricPendingBytes)
	rejectsBefore := testutil.ToFloat64(metricRejectedEntries.WithLabelValues("overflow"))
	var accepted, rejected int
	for i := 0; i < 2000; i++ {
		err := p.WriteIndex(context.Background(), []string{strings.Repeat("x", 500)}, fmt.Sprint(i))
		switch {
		case errors.Is(err, bundler.ErrOverflow):
			rejected++
		case err != nil:
			t.Fatal(err)
		default:
			accepted++
		}
	}
	if accepted == 0 || rejected == 0 {
		t.Fatalf("accepted=%d rejected=%d", accepted, rejected)
	}
	if got := testutil.ToFloat64(metricPendingBytes) - pendingBefore; got > float64(b.BufferedByteLimit) {
		t.Fatalf("buffer exceeded limit: %v", got)
	}
	if got := testutil.ToFloat64(metricRejectedEntries.WithLabelValues("overflow")) - rejectsBefore; got != float64(rejected) {
		t.Fatalf("unreported rejections: %v/%d", got, rejected)
	}
	if growth := runtime.NumGoroutine() - beforeGoroutines; growth > 20 {
		t.Fatalf("goroutines grew with entries: %d", growth)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := p.shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("real MySQL cancellation did not finish promptly")
	}
	unlock()
	await(t, func() bool { return testutil.ToFloat64(metricPendingBytes) == pendingBefore })
}

func TestMySQLConnectionLossAndRecovery(t *testing.T) {
	p, db := integrationProvider(t)
	unlock := lockIndex(t, db)
	retries := testutil.ToFloat64(metricBatchWriteRetries)
	if err := p.WriteIndex(context.Background(), []string{"recovered"}, "uuid"); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { p.Flush(); close(done) }()
	var id int64
	await(t, func() bool {
		err := db.Get(&id, `SELECT ID FROM information_schema.PROCESSLIST WHERE INFO LIKE 'INSERT IGNORE INTO EntryIndex%' LIMIT 1`)
		return err == nil
	})
	if _, err := db.Exec(fmt.Sprintf("KILL CONNECTION %d", id)); err != nil {
		t.Fatal(err)
	}
	unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("write did not recover")
	}
	if testutil.ToFloat64(metricBatchWriteRetries) <= retries {
		t.Fatal("connection failure did not exercise retry")
	}
	got, err := p.LookupIndices(context.Background(), []string{"recovered"})
	if err != nil || len(got) != 1 || got[0] != "uuid" {
		t.Fatalf("lookup after recovery: %v, %v", got, err)
	}
	// Verify the worker accepts later entries without restarting the provider.
	if err := p.WriteIndex(context.Background(), []string{"later"}, "uuid2"); err != nil {
		t.Fatal(err)
	}
	p.Flush()
	got, err = p.LookupIndices(context.Background(), []string{"later"})
	if err != nil || len(got) != 1 {
		t.Fatalf("later write: %v, %v", got, err)
	}
}

func TestMySQLDeadlockRecovery(t *testing.T) {
	p, db := integrationProvider(t)
	// Make the competing transaction more expensive to roll back so InnoDB picks
	// the smaller batch transaction as its deadlock victim.
	var weight []indexEntry
	for i := 0; i < 3000; i++ {
		weight = append(weight, indexEntry{Key: fmt.Sprintf("weight%04d", i), UUID: "old"})
	}
	weight = append(weight, indexEntry{Key: "z", UUID: "uuid"})
	if err := execChunks(context.Background(), db, weight); err != nil {
		t.Fatal(err)
	}
	// Avoid gap locks on the weight range blocking the first chunk before the
	// intended two-row deadlock can form.
	tx, err := db.BeginTxx(context.Background(), &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec("UPDATE EntryIndex SET EntryUUID='heavy' WHERE EntryKey LIKE 'weight%'"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("UPDATE EntryIndex SET EntryUUID='uuid' WHERE EntryKey='z'"); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 1001)
	for i := 0; i < 1000; i++ {
		keys[i] = fmt.Sprintf("a%04d", i)
	}
	keys[1000] = "z"
	retries := testutil.ToFloat64(metricBatchWriteRetries)
	if err := p.WriteIndex(context.Background(), keys, "uuid"); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { p.Flush(); close(done) }()
	await(t, func() bool {
		var count int
		err := db.Get(&count, `SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE INFO LIKE 'INSERT IGNORE INTO EntryIndex%' AND INFO LIKE '%z%'`)
		return err == nil && count > 0
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := tx.ExecContext(ctx, "INSERT IGNORE INTO EntryIndex (EntryKey,EntryUUID) VALUES ('a0000','uuid')"); err != nil {
		t.Fatalf("competing transaction should survive: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("batch did not recover from deadlock")
	}
	if testutil.ToFloat64(metricBatchWriteRetries) <= retries {
		t.Fatal("deadlock did not exercise batch retry")
	}
	var count int
	if err := db.Get(&count, "SELECT COUNT(*) FROM EntryIndex WHERE EntryUUID='uuid'"); err != nil || count != 1001 {
		t.Fatalf("partial batch after deadlock: %d, %v", count, err)
	}
}

func TestMySQLStartupTimeout(t *testing.T) {
	if os.Getenv("REKOR_INDEX_TEST_DSN") == "" {
		t.Skip("integration test")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(io.Discard, conn) // Never send a MySQL handshake.
	}()
	start := time.Now()
	p, err := NewProvider("test@tcp(" + listener.Addr().String() + ")/test")
	if p != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("startup: %v, %v", p, err)
	}
	if time.Since(start) > startupTimeout+time.Second {
		t.Fatal("startup exceeded its deadline")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed startup leaked connection")
	}
}

// Exercise the fleet's 21 writer slots with shared keys and opposite input
// orders. Each bundle spans two SQL statements in one transaction.
func TestMySQLConcurrentHotKeyBundles(t *testing.T) {
	p, db := integrationProvider(t)
	const writers = 21
	const keysPerEntry = 1001
	p.writeDB.SetMaxOpenConns(writers)
	b := p.initBundler()
	b.HandlerLimit = writers
	b.BundleCountThreshold = 1
	failedBefore := testutil.ToFloat64(metricBatchWrites.WithLabelValues("false"))
	for round := 0; round < 3; round++ {
		// Hold the table while all bundles enter their handlers, then release
		// them together to avoid accidentally testing serial execution.
		unlock := lockIndex(t, db)
		for writer := 0; writer < writers; writer++ {
			keys := make([]string, keysPerEntry)
			for i := range keys {
				n := i
				if writer%2 == 0 {
					n = keysPerEntry - 1 - i
				}
				keys[i] = fmt.Sprintf("hot%04d", n)
			}
			if err := p.WriteIndex(context.Background(), keys, fmt.Sprintf("uuid%02d", writer)); err != nil {
				unlock()
				t.Fatal(err)
			}
		}
		await(t, func() bool { return p.writeDB.Stats().InUse == writers })
		unlock()
		done := make(chan struct{})
		go func() { p.Flush(); close(done) }()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Fatal("hot-key bundles did not drain")
		}
		var count int
		if err := db.Get(&count, "SELECT COUNT(*) FROM EntryIndex"); err != nil || count != writers*keysPerEntry {
			t.Fatalf("round %d: incomplete index: rows=%d, error=%v", round, count, err)
		}
		// Subsequent rounds repeat identical PK pairs, exercising INSERT IGNORE
		// duplicate locking as well as the first round's fresh inserts.
	}
	if got := testutil.ToFloat64(metricBatchWrites.WithLabelValues("false")); got != failedBefore {
		t.Fatal("concurrent hot-key bundles exhausted their retries")
	}
}
