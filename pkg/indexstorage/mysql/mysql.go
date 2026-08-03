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
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sigstore/rekor/pkg/log"

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
)

// IndexStorageProvider implements indexstorage.IndexStorage
//
// Reads and writes use independent connection pools against the same DSN.
// LookupIndices runs synchronously in the HTTP request path while WriteIndex is
// dispatched from a detached goroutine per entry, so a shared pool lets a burst
// of writes queue ahead of every read. database/sql wakes a uniformly random
// waiter rather than the longest-waiting one, so reads cannot be prioritized
// within a pool no matter how large it is.
type IndexStorageProvider struct {
	readDB    *sqlx.DB
	writeDB   *sqlx.DB
	collector *dbStatsCollector
}

func NewProvider(dsn string, opts ...Options) (*IndexStorageProvider, error) {
	provider := &IndexStorageProvider{}

	readDB, err := openPool(dsn, poolRead, opts)
	if err != nil {
		return nil, err
	}
	provider.readDB = readDB

	writeDB, err := openPool(dsn, poolWrite, opts)
	if err != nil {
		return nil, errors.Join(err, readDB.Close())
	}
	provider.writeDB = writeDB

	if _, err := provider.writeDB.Exec(createTableStmt); err != nil {
		return nil, errors.Join(fmt.Errorf("create table if not exists failed: %w", err), provider.Shutdown())
	}

	provider.collector = &dbStatsCollector{readDB: provider.readDB, writeDB: provider.writeDB}
	if err := prometheus.DefaultRegisterer.Register(provider.collector); err != nil {
		provider.collector = nil
		var alreadyRegistered prometheus.AlreadyRegisteredError
		if !errors.As(err, &alreadyRegistered) {
			return nil, errors.Join(fmt.Errorf("registering db stats collector: %w", err), provider.Shutdown())
		}
		log.Logger.Warnf("search index db stats already registered by another provider; this provider's pools will not be reported")
	}

	// a limit of 0 means unlimited, so report what each pool actually got
	log.Logger.Infof("search index connection pools: %d read, %d write",
		provider.readDB.Stats().MaxOpenConnections, provider.writeDB.Stats().MaxOpenConnections)

	return provider, nil
}

// openPool opens one connection pool, applying only the options that name role.
func openPool(dsn string, role poolRole, opts []Options) (*sqlx.DB, error) {
	db, err := sqlx.Open(ProviderType, dsn)
	if err != nil {
		return nil, fmt.Errorf("opening %s pool: %w", role, err)
	}
	if err := db.Ping(); err != nil {
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

// WriteIndex adds the index for the specified keys.
func (isp *IndexStorageProvider) WriteIndex(ctx context.Context, keys []string, index string) error {
	if isp.writeDB == nil {
		return errors.New("sql client has not been initialized")
	}

	valueMaps := make([]map[string]interface{}, 0, len(keys))
	for _, key := range keys {
		valueMaps = append(valueMaps, map[string]interface{}{"key": key, "uuid": index})
	}
	result, err := isp.writeDB.NamedExecContext(ctx, writeStmt, valueMaps)
	if err != nil {
		return fmt.Errorf("mysql write error: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("mysql error getting rowsAffected: %w", err)
	}
	log.ContextLogger(ctx).Debugf("WriteIndex affected %d rows", rowsAffected)
	return nil
}

// Shutdown cleans up any client resources that may be held by the provider
func (isp *IndexStorageProvider) Shutdown() error {
	// a registered collector keeps reporting the closed pools as all-zero, and blocks a
	// replacement provider from registering its own
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
