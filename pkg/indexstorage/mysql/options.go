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
	"time"

	"github.com/jmoiron/sqlx"
)

// Options configures connections to the MySQL index storage system
type Options interface {
	applyConnMaxIdleTime(*sqlx.DB)
	applyConnMaxLifetime(*sqlx.DB)
	applyMaxIdleConns(*sqlx.DB)
	applyMaxOpenConns(*sqlx.DB)
}

// NoOpOptionImpl implements the MySQLOption interfaces as no-ops.
type noOpOptionImpl struct{}

// applyConnMaxIdleTime is a no-op required to fully implement the requisite interfaces
func (noOpOptionImpl) applyConnMaxIdleTime(_ *sqlx.DB) {}

// ApplyConnMaxLifetime is a no-op required to fully implement the requisite interfaces
func (noOpOptionImpl) applyConnMaxLifetime(_ *sqlx.DB) {}

// ApplyMaxOpenConns is a no-op required to fully implement the requisite interfaces
func (noOpOptionImpl) applyMaxOpenConns(_ *sqlx.DB) {}

// ApplyMaxIdleConns is a no-op required to fully implement the requisite interfaces
func (noOpOptionImpl) applyMaxIdleConns(_ *sqlx.DB) {}

// RequestConnMaxIdleTime implements the functional option pattern for specifying the maximum connection idle time
type RequestConnMaxIdleTime struct {
	noOpOptionImpl
	idleTime time.Duration
}

// applyConnMaxIdleTime sets the maximum connection idle time
func (r RequestConnMaxIdleTime) applyConnMaxIdleTime(db *sqlx.DB) {
	if db != nil {
		db.SetConnMaxIdleTime(r.idleTime)
	}
}

// WithConnMaxIdleTime specifies the maximum connection idle time
func WithConnMaxIdleTime(idleTime time.Duration) RequestConnMaxIdleTime {
	return RequestConnMaxIdleTime{idleTime: idleTime}
}

// RequestConnMaxLifetime implements the functional option pattern for specifying the maximum connection lifetime
type RequestConnMaxLifetime struct {
	noOpOptionImpl
	lifetime time.Duration
}

// ApplyConnMaxLifetime sets the maximum connection lifetime
func (r RequestConnMaxLifetime) applyConnMaxLifetime(db *sqlx.DB) {
	if db != nil {
		db.SetConnMaxLifetime(r.lifetime)
	}
}

// WithConnMaxLifetime specifies the maximum connection lifetime
func WithConnMaxLifetime(lifetime time.Duration) RequestConnMaxLifetime {
	return RequestConnMaxLifetime{lifetime: lifetime}
}

// RequestMaxIdleConns implements the functional option pattern for specifying the maximum number of idle connections
type RequestMaxIdleConns struct {
	noOpOptionImpl
	idleConns int
}

// ApplyMaxIdleConns sets the maximum number of idle connections
func (r RequestMaxIdleConns) applyMaxIdleConns(db *sqlx.DB) {
	if db != nil {
		db.SetMaxIdleConns(r.idleConns)
	}
}

// WithMaxIdleConns specifies the maximum number of idle connections
func WithMaxIdleConns(idleConns int) RequestMaxIdleConns {
	return RequestMaxIdleConns{idleConns: idleConns}
}

// RequestMaxOpenConns implements the functional option pattern for specifying the maximum number of open connections
type RequestMaxOpenConns struct {
	noOpOptionImpl
	openConns int
}

// applyMaxOpenConns sets the maximum number of open connections
func (r RequestMaxOpenConns) applyMaxOpenConns(db *sqlx.DB) {
	if db != nil {
		db.SetMaxOpenConns(r.openConns)
	}
}

// WithMaxOpenConns specifies the maximum number of open connections
func WithMaxOpenConns(openConns int) RequestMaxOpenConns {
	return RequestMaxOpenConns{openConns: openConns}
}
