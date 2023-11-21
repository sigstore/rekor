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
	"github.com/sigstore/rekor/pkg/log"
	"github.com/spf13/viper"

	// this imports the mysql driver for go
	_ "github.com/go-sql-driver/mysql"
)

const (
	ProviderType = "mysql"

	lookupStmt      = "SELECT EntryUUIDs FROM EntryIndex WHERE EntryKey IN (?)"
	writeStmt       = "INSERT IGNORE INTO EntryIndex (EntryKey, EntryUUIDs) VALUES (:key, :uuid)"
	createTableStmt = `CREATE TABLE IF NOT EXISTS EntryIndex (
		PK BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		EntryKey varchar(512) NOT NULL,
		EntryUUIDs char(80) NOT NULL,
		PRIMARY KEY(PK),
		UNIQUE(EntryKey, EntryUUIDs)
	)`
)

// IndexStorageProvider implements indexstorage.IndexStorage
type IndexStorageProvider struct {
	db *sqlx.DB
}

func NewProvider(dsn string) (*IndexStorageProvider, error) {
	var err error
	provider := &IndexStorageProvider{}
	provider.db, err = sqlx.Open(ProviderType, dsn)
	if err != nil {
		return nil, err
	}
	if err = provider.db.Ping(); err != nil {
		return nil, err
	}

	provider.db.SetConnMaxIdleTime(viper.GetDuration("search_index.mysql.conn_max_idletime"))
	provider.db.SetConnMaxLifetime(viper.GetDuration("search_index.mysql.conn_max_lifetime"))
	provider.db.SetMaxOpenConns(viper.GetInt("search_index.mysql.max_open_connections"))
	provider.db.SetMaxIdleConns(viper.GetInt("search_index.mysql.max_idle_connections"))

	if _, err := provider.db.Exec(createTableStmt); err != nil {
		return nil, fmt.Errorf("create table if not exists failed: %w", err)
	}

	return provider, nil
}

// LookupIndices looks up and returns all indices for the specified keys. The key value(s) will be canonicalized
// by converting all characters into a lowercase value before looking up in Redis
func (isp *IndexStorageProvider) LookupIndices(ctx context.Context, keys []string) ([]string, error) {
	if isp.db == nil {
		return []string{}, errors.New("sql client has not been initialized")
	}

	query, args, err := sqlx.In(lookupStmt, keys)
	if err != nil {
		return []string{}, fmt.Errorf("error preparing statement: %w", err)
	}
	rows, err := isp.db.QueryContext(ctx, isp.db.Rebind(query), args...)
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

// WriteIndex adds the index for the specified key. The key value will be canonicalized
// by converting all characters into a lowercase value before appending the index in Redis
func (isp *IndexStorageProvider) WriteIndex(ctx context.Context, keys []string, index string) error {
	if isp.db == nil {
		return errors.New("sql client has not been initialized")
	}

	var valueMaps []map[string]interface{}
	for _, key := range keys {
		valueMaps = append(valueMaps, map[string]interface{}{"key": key, "uuid": index})
	}
	result, err := isp.db.NamedExecContext(ctx, writeStmt, valueMaps)
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
	if isp.db == nil {
		return nil
	}

	return isp.db.Close()
}
