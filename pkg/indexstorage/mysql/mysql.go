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
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/cenkalti/backoff/v4"
	"github.com/jmoiron/sqlx"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sigstore/rekor/pkg/log"
	"google.golang.org/api/support/bundler"

	// this imports the mysql driver for go
	_ "github.com/go-sql-driver/mysql"
)

const (
	ProviderType = "mysql"

	lookupStmt      = "SELECT EntryUUID FROM EntryIndex WHERE EntryKey IN (?)"
	writeStmt       = "INSERT IGNORE INTO EntryIndex (EntryKey, EntryUUID) VALUES (:key, :uuid)"
	createTableStmt = `CREATE TABLE IF NOT EXISTS EntryIndex (
		EntryKey varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
		EntryUUID char(80) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
		PRIMARY KEY(EntryKey, EntryUUID)
	)`

	// EntryKey's varchar(512) counts characters, not bytes. INSERT IGNORE downgrades a
	// too-long value to a warning and truncates it, storing a row no lookup can ever
	// match, so oversized keys are dropped before they reach the database.
	maxEntryKeyChars = 512

	// Bound caller-controlled fan-out before allocating rows or reserving buffer
	// capacity. Oversized entries are rejected as a whole, not partially indexed.
	maxIndexKeysPerEntry = 8192

	// This is a hard limit, including when the bundler coalesces a queued tail.
	// Together with row size accounting it bounds SQL work per attempt, rather
	// than merely bounding the number of entries (which can have many keys).
	bundleByteLimit = 1 << 20

	// index writes are coalesced across entries so a burst of uploads costs a few wide
	// INSERTs instead of one per entry. The delay bounds coalescing, not database queueing.
	// The count is of entries, not rows, since each entry is buffered as a single item.
	bundleDelay = 250 * time.Millisecond
	bundleCount = 100

	// the write pool is unlimited by default, in which case the bundler would otherwise
	// fall back to its own default of 1 and serialize every index write.
	defaultHandlerLimit = 8

	// backpressure ceiling: Add fails once this many bytes of keys are buffered, so a
	// MySQL outage surfaces as an error instead of growing the heap without bound.
	bufferedByteLimit = 32 << 20

	// Bundles have hard entry-count and byte limits and do not inherit the caller's
	// deadline. Each bounded attempt gets its own timeout.
	bundleWriteTimeout = 5 * time.Second

	// a failed bundle costs up to bundleCount entries their index keys, so transient errors
	// (a dropped connection, a failover) are retried. Attempts are capped because a bundle
	// holds one of the HandlerLimit slots for as long as it is retrying.
	bundleWriteRetries      = 2
	bundleRetryInitialDelay = 100 * time.Millisecond

	// bundleCount bounds entries rather than rows, and an entry's key count is up to the
	// client, so a bundle is split into INSERTs of at most this many rows. That stays far
	// below both the 65,535 placeholder limit on server-side prepared statements (two per
	// row), which applies when the DSN omits interpolateParams=true, and max_allowed_packet.
	maxRowsPerInsert = 1000

	// ceiling on the shutdown drain, chosen to leave the rest of StopAPI room inside a
	// typical 30s container termination grace period.
	shutdownDrainTimeout = 10 * time.Second
	shutdownCancelGrace  = time.Second
	startupTimeout       = 10 * time.Second
)

// IndexStorageProvider implements indexstorage.IndexStorage
//
// Reads and writes use independent connection pools against the same DSN.
// LookupIndices runs synchronously in the HTTP request path while WriteIndex only
// buffers, leaving the insert to a bundler goroutine, so a shared pool would let a
// burst of writes queue ahead of every read. database/sql wakes a uniformly random
// waiter rather than the longest-waiting one, so reads cannot be prioritized
// within a pool no matter how large it is.
type IndexStorageProvider struct {
	readDB      *sqlx.DB
	writeDB     *sqlx.DB
	collector   *dbStatsCollector
	bundler     *bundler.Bundler
	bundlerOnce sync.Once
	batchDelay  time.Duration

	// closeMu orders WriteIndex against Shutdown: once closed is set, no key can be
	// buffered after the drain has started and left behind in a bundle nobody waits for.
	closeMu sync.RWMutex
	closed  bool
	// Cancel outstanding SQL calls and retry sleeps when the drain deadline expires.
	writeCtx     context.Context
	cancelWrites context.CancelFunc
	shutdownOnce sync.Once
	shutdownErr  error
}

// indexEntry is one row of writeStmt; the tags name writeStmt's bind parameters.
type indexEntry struct {
	Key  string `db:"key"`
	UUID string `db:"uuid"`
}

// Include both string headers as well as payload so tiny keys still consume buffer capacity.
func (e indexEntry) size() int { return len(e.Key) + len(e.UUID) + 32 }

// errShutdown is returned by WriteIndex once Shutdown has begun.
var errShutdown = errors.New("search index storage is shut down")

func NewProvider(dsn string, opts ...Options) (*IndexStorageProvider, error) {
	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()
	provider := &IndexStorageProvider{}
	for _, o := range opts {
		o.applyBatchDelay(&provider.batchDelay)
	}

	readDB, err := openPool(ctx, dsn, poolRead, opts)
	if err != nil {
		return nil, err
	}
	provider.readDB = readDB

	writeDB, err := openPool(ctx, dsn, poolWrite, opts)
	if err != nil {
		return nil, errors.Join(err, readDB.Close())
	}
	provider.writeDB = writeDB

	if _, err := provider.writeDB.ExecContext(ctx, createTableStmt); err != nil {
		return nil, errors.Join(fmt.Errorf("create table if not exists failed: %w", err), provider.Shutdown())
	}

	collector := &dbStatsCollector{readDB: provider.readDB, writeDB: provider.writeDB}
	if err := prometheus.DefaultRegisterer.Register(collector); err != nil {
		return nil, errors.Join(fmt.Errorf("registering db stats collector: %w", err), provider.Shutdown())
	}
	provider.collector = collector

	// HandlerLimit derives from the write pool's limit, so the bundler cannot be built
	// until openPool has applied the options
	provider.initBundler()

	// a limit of 0 means unlimited, so report what each pool actually got
	log.Logger.Infof("search index connection pools: %d read, %d write",
		provider.readDB.Stats().MaxOpenConnections, provider.writeDB.Stats().MaxOpenConnections)

	return provider, nil
}

func (isp *IndexStorageProvider) initBundler() *bundler.Bundler {
	isp.bundlerOnce.Do(func() {
		isp.writeCtx, isp.cancelWrites = context.WithCancel(context.Background())
		// the item is all of one entry's rows, so an entry is buffered, bundled and
		// written all-or-nothing rather than split across bundles
		b := bundler.NewBundler([]indexEntry{}, isp.writeBundle)
		b.DelayThreshold = bundleDelay
		if isp.batchDelay > 0 {
			b.DelayThreshold = isp.batchDelay
		}
		b.BundleCountThreshold = bundleCount
		b.BundleByteThreshold = bundleByteLimit
		b.BundleByteLimit = bundleByteLimit
		b.BufferedByteLimit = bufferedByteLimit
		b.HandlerLimit = defaultHandlerLimit
		// more concurrent bundles than connections would just queue inside the pool
		if isp.writeDB != nil {
			if maxConns := isp.writeDB.Stats().MaxOpenConnections; maxConns > 0 {
				b.HandlerLimit = maxConns
			}
		}
		isp.bundler = b
	})
	return isp.bundler
}

// writeBundle inserts one coalesced batch of index entries, retrying transient failures.
// WriteIndex has long since returned, so a failure here is only observable through these
// metrics and logs; the entries in a bundle that exhausts its retries stay unsearchable.
func (isp *IndexStorageProvider) writeBundle(items any) {
	bundle := items.([][]indexEntry)
	defer func() {
		bytes := 0
		for _, rows := range bundle {
			for _, row := range rows {
				bytes += row.size()
			}
		}
		metricPendingEntries.Sub(float64(len(bundle)))
		metricPendingBytes.Sub(float64(bytes))
	}()
	var entries []indexEntry
	for _, rows := range bundle {
		entries = append(entries, rows...)
	}

	// Order the entire transaction before chunking, independently of arrival order.
	// Folding case reduces lock-order inversions for common ASCII index keys.
	// This is not an implementation of utf8mb4_general_ci (which also folds
	// accents, for example), and InnoDB gap/duplicate locks can still deadlock.
	// Keep the bounded transaction retries even with deterministic ordering.
	slices.SortFunc(entries, func(a, b indexEntry) int {
		if c := strings.Compare(strings.ToLower(a.Key), strings.ToLower(b.Key)); c != 0 {
			return c
		}
		if c := strings.Compare(a.UUID, b.UUID); c != 0 {
			return c
		}
		return strings.Compare(a.Key, b.Key)
	})

	start := time.Now()
	attempts := 0
	err := backoff.RetryNotify(func() error {
		if err := isp.writeCtx.Err(); err != nil {
			return backoff.Permanent(err)
		}
		attempts++
		ctx, cancel := context.WithTimeout(isp.writeCtx, bundleWriteTimeout)
		defer cancel()
		return isp.execBundle(ctx, entries)
	}, backoff.WithContext(newBundleBackOff(), isp.writeCtx), func(err error, wait time.Duration) {
		metricBatchWriteRetries.Inc()
		log.Logger.Warnf("batched WriteIndex of %d entries (%d keys) failed, retrying in %s: %v", len(bundle), len(entries), wait, err)
	})
	labels := prometheus.Labels{"success": strconv.FormatBool(err == nil)}
	metricBatchWrites.With(labels).Inc()
	metricBatchWriteRows.With(labels).Add(float64(len(entries)))
	metricBatchWriteLatency.With(labels).Observe(time.Since(start).Seconds())

	if err != nil {
		log.Logger.Errorf("batched WriteIndex of %d entries (%d keys) failed after %d attempts; those keys may require backfill-index: %v",
			len(bundle), len(entries), attempts, err)
	}
}

// newBundleBackOff bounds retries by count rather than elapsed time, since each attempt
// already carries its own bundleWriteTimeout.
func newBundleBackOff() backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = bundleRetryInitialDelay
	b.MaxElapsedTime = 0
	return backoff.WithMaxRetries(b, bundleWriteRetries)
}

// execBundle writes entries in INSERTs of at most maxRowsPerInsert rows. Multi-statement
// bundles use a transaction so a failure cannot leave an entry indexed under only the
// keys that happened to occur in earlier chunks. Retrying after an ambiguous commit is
// safe because writeStmt is an INSERT IGNORE.
func (isp *IndexStorageProvider) execBundle(ctx context.Context, entries []indexEntry) error {
	if len(entries) <= maxRowsPerInsert {
		return execChunks(ctx, isp.writeDB, entries)
	}

	tx, err := isp.writeDB.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql begin batch transaction: %w", err)
	}
	defer func() {
		// Rollback is a no-op after Commit and ensures every error path releases the
		// transaction. The original operation error is more useful than rollback's.
		_ = tx.Rollback()
	}()
	if err := execChunks(ctx, tx, entries); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("mysql commit batch transaction: %w", err)
	}
	return nil
}

type namedExecer interface {
	NamedExecContext(context.Context, string, any) (sql.Result, error)
}

func execChunks(ctx context.Context, db namedExecer, entries []indexEntry) error {
	for chunk := range slices.Chunk(entries, maxRowsPerInsert) {
		result, err := db.NamedExecContext(ctx, writeStmt, chunk)
		if err != nil {
			return fmt.Errorf("mysql write error: %w", err)
		}
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("mysql error getting rowsAffected: %w", err)
		}
		log.Logger.Debugf("WriteIndex affected %d rows", rowsAffected)
	}
	return nil
}

// openPool opens one connection pool, applying only the options that name role.
func openPool(ctx context.Context, dsn string, role poolRole, opts []Options) (*sqlx.DB, error) {
	db, err := sqlx.Open(ProviderType, dsn)
	if err != nil {
		return nil, fmt.Errorf("opening %s pool: %w", role, err)
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, errors.Join(fmt.Errorf("pinging %s pool: %w", role, err), db.Close())
	}

	for _, o := range opts {
		o.applyConnMaxIdleTime(db)
		o.applyConnMaxLifetime(db)
		o.applyMaxIdleConns(db, role)
		o.applyMaxOpenConns(db, role)
	}
	return db, nil
}

// LookupIndices looks up and returns all indices for the specified keys.
func (isp *IndexStorageProvider) LookupIndices(ctx context.Context, keys []string) ([]string, error) {
	if isp.readDB == nil {
		return []string{}, errors.New("sql client has not been initialized")
	}

	query, args, err := sqlx.In(lookupStmt, keys)
	if err != nil {
		return []string{}, fmt.Errorf("error preparing statement: %w", err)
	}
	rows, err := isp.readDB.QueryContext(ctx, isp.readDB.Rebind(query), args...)
	if err != nil {
		return []string{}, fmt.Errorf("error looking up indices from mysql: %w", err)
	}
	defer rows.Close()

	var entryUUIDs []string
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			return []string{}, fmt.Errorf("error parsing results from mysql: %w", err)
		}
		entryUUIDs = append(entryUUIDs, result)
	}

	if err := rows.Err(); err != nil {
		return []string{}, fmt.Errorf("error processing results from mysql: %w", err)
	}
	return entryUUIDs, nil
}

// WriteIndex queues the index for the specified keys. The rows are written
// asynchronously in coalesced batches, so a nil return only means the keys were
// buffered; MySQL failures are reported by writeBundle. Call Flush to wait for them.
// Exact duplicate keys are charged once. Entries exceeding the key-count or byte
// limit are rejected before buffering, without indexing a partial set of keys.
func (isp *IndexStorageProvider) WriteIndex(ctx context.Context, keys []string, index string) error {
	if isp.writeDB == nil {
		return errors.New("sql client has not been initialized")
	}

	// an entry indexed under some of its keys but not others is worse than one indexed
	// under none, so all of its rows are buffered as one item
	rows := make([]indexEntry, 0, min(len(keys), maxIndexKeysPerEntry))
	seen := make(map[string]struct{}, min(len(keys), maxIndexKeysPerEntry))
	// Count skipped occurrences without retaining an unbounded set of invalid
	// keys. Aggregate metrics and emit one fixed-message warning, including on
	// early rejection, rather than amplifying one request into per-key log writes.
	invalidUTF8, oversized := 0, 0
	defer func() {
		if invalidUTF8 == 0 && oversized == 0 {
			return
		}
		metricInvalidUTF8Keys.Add(float64(invalidUTF8))
		metricSkippedKeys.Add(float64(oversized))
		log.ContextLogger(ctx).Warnw("skipping invalid search index keys",
			"entry_id", index, "invalid_utf8_keys", invalidUTF8, "oversized_keys", oversized)
	}()

	size := 0
	for _, key := range keys {
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		// INSERT IGNORE must not silently alter an invalid utf8mb4 key.
		if !utf8.ValidString(key) {
			invalidUTF8++
			continue
		}
		// a key of at most maxEntryKeyChars bytes cannot exceed maxEntryKeyChars characters
		if len(key) > maxEntryKeyChars {
			if n := utf8.RuneCountInString(key); n > maxEntryKeyChars {
				oversized++
				continue
			}
		}
		entry := indexEntry{Key: key, UUID: index}
		if len(rows) == maxIndexKeysPerEntry || entry.size() > bundleByteLimit-size {
			metricRejectedEntries.WithLabelValues("oversized").Inc()
			return fmt.Errorf("index entry %s exceeds %d unique keys or %d accounted bytes: %w",
				index, maxIndexKeysPerEntry, bundleByteLimit, bundler.ErrOversizedItem)
		}
		seen[key] = struct{}{}
		rows = append(rows, entry)
		size += entry.size()
	}
	if len(rows) == 0 {
		return nil
	}
	// Deduplication can leave a large unused backing array. Do not retain that
	// allocation while charging the queue for only the surviving row headers.
	if len(rows) != cap(rows) {
		compact := make([]indexEntry, len(rows))
		copy(compact, rows)
		rows = compact
	}

	isp.closeMu.RLock()
	defer isp.closeMu.RUnlock()
	if isp.closed {
		metricRejectedEntries.WithLabelValues("shutdown").Inc()
		return fmt.Errorf("buffering index keys for entry %s: %w", index, errShutdown)
	}
	metricPendingEntries.Inc()
	metricPendingBytes.Add(float64(size))
	if err := isp.initBundler().Add(rows, size); err != nil {
		metricPendingEntries.Dec()
		metricPendingBytes.Sub(float64(size))
		reason := "overflow"
		if errors.Is(err, bundler.ErrOversizedItem) {
			reason = "oversized"
		}
		metricRejectedEntries.WithLabelValues(reason).Inc()
		return fmt.Errorf("buffering index keys for entry %s: %w", index, err)
	}
	return nil
}

// Flush waits for all buffered entries to be written to the database. It goes through
// initBundler rather than reading the field, since a detached WriteIndex goroutine may
// still be racing to create the bundler.
func (isp *IndexStorageProvider) Flush() {
	isp.initBundler().Flush()
}

// Shutdown cleans up any client resources that may be held by the provider
func (isp *IndexStorageProvider) Shutdown() error {
	isp.shutdownOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownDrainTimeout)
		defer cancel()
		isp.shutdownErr = isp.shutdown(ctx)
	})
	return isp.shutdownErr
}

// shutdown bounds the caller's wait even if a driver fails to honor cancellation.
// The cleanup worker retains ownership of resources until it exits.
func (isp *IndexStorageProvider) shutdown(ctx context.Context) error {
	isp.closeMu.Lock()
	isp.closed = true
	isp.closeMu.Unlock()
	isp.initBundler()
	done := make(chan error, 1)
	go func() {
		isp.Flush()
		isp.cancelWrites()
		done <- isp.closePools()
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		metricShutdownTimeouts.Inc()
		isp.cancelWrites()
		drainErr := fmt.Errorf("search index buffer did not drain; buffered keys may require backfill-index: %w", ctx.Err())
		select {
		case err := <-done:
			return errors.Join(drainErr, err)
		case <-time.After(shutdownCancelGrace):
			return fmt.Errorf("search index cleanup exceeded cancellation grace: %w", drainErr)
		}
	}
}

func (isp *IndexStorageProvider) closePools() error {
	// a registered collector keeps reporting the closed pools as all-zero
	if isp.collector != nil {
		prometheus.DefaultRegisterer.Unregister(isp.collector)
		isp.collector = nil
	}

	var errs []error
	if isp.readDB != nil {
		errs = append(errs, isp.readDB.Close())
	}
	if isp.writeDB != nil {
		errs = append(errs, isp.writeDB.Close())
	}
	return errors.Join(errs...)
}
