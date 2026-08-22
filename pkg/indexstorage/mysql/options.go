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

// Options configures connections to the MySQL index storage system.
//
// The read and write pools are sized independently, so the connection limit options name
// the pool they configure and are ignored when the other pool is being opened.
type Options interface {
	applyConnMaxIdleTime(*sqlx.DB)
	applyConnMaxLifetime(*sqlx.DB)
	applyMaxIdleConns(*sqlx.DB, poolRole)
	applyMaxOpenConns(*sqlx.DB, poolRole)
}

// NoOpOptionImpl implements the MySQLOption interfaces as no-ops.
type noOpOptionImpl struct{}

// applyConnMaxIdleTime is a no-op required to fully implement the requisite interfaces
func (noOpOptionImpl) applyConnMaxIdleTime(_ *sqlx.DB) {}

// ApplyConnMaxLifetime is a no-op required to fully implement the requisite interfaces
func (noOpOptionImpl) applyConnMaxLifetime(_ *sqlx.DB) {}

// ApplyMaxOpenConns is a no-op required to fully implement the requisite interfaces
func (noOpOptionImpl) applyMaxOpenConns(_ *sqlx.DB, _ poolRole) {}

// ApplyMaxIdleConns is a no-op required to fully implement the requisite interfaces
func (noOpOptionImpl) applyMaxIdleConns(_ *sqlx.DB, _ poolRole) {}

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

// RequestMaxIdleConns implements the functional option pattern for specifying the maximum
// number of idle connections in one pool
type RequestMaxIdleConns struct {
	noOpOptionImpl
	role      poolRole
	idleConns int
}

// ApplyMaxIdleConns sets the maximum number of idle connections, if db is the pool this
// option was built for
func (r RequestMaxIdleConns) applyMaxIdleConns(db *sqlx.DB, role poolRole) {
	if db != nil && role == r.role {
		db.SetMaxIdleConns(r.idleConns)
	}
}

// WithReadMaxIdleConns specifies the maximum number of idle connections in the read pool
func WithReadMaxIdleConns(idleConns int) RequestMaxIdleConns {
	return RequestMaxIdleConns{role: poolRead, idleConns: idleConns}
}

// WithWriteMaxIdleConns specifies the maximum number of idle connections in the write pool
func WithWriteMaxIdleConns(idleConns int) RequestMaxIdleConns {
	return RequestMaxIdleConns{role: poolWrite, idleConns: idleConns}
}

// RequestMaxOpenConns implements the functional option pattern for specifying the maximum
// number of open connections in one pool
type RequestMaxOpenConns struct {
	noOpOptionImpl
	role      poolRole
	openConns int
}

// applyMaxOpenConns sets the maximum number of open connections, if db is the pool this
// option was built for
func (r RequestMaxOpenConns) applyMaxOpenConns(db *sqlx.DB, role poolRole) {
	if db != nil && role == r.role {
		db.SetMaxOpenConns(r.openConns)
	}
}

// WithReadMaxOpenConns specifies the maximum number of open connections in the read pool
func WithReadMaxOpenConns(openConns int) RequestMaxOpenConns {
	return RequestMaxOpenConns{role: poolRead, openConns: openConns}
}

// WithWriteMaxOpenConns specifies the maximum number of open connections in the write pool
func WithWriteMaxOpenConns(openConns int) RequestMaxOpenConns {
	return RequestMaxOpenConns{role: poolWrite, openConns: openConns}
}

// poolRole identifies which of the provider's two connection pools is being configured.
type poolRole int

const (
	poolRead poolRole = iota
	poolWrite
)

func (r poolRole) String() string {
	if r == poolWrite {
		return "write"
	}
	return "read"
}
