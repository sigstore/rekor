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
	"github.com/jmoiron/sqlx"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	openConnsDesc = prometheus.NewDesc(
		"rekor_index_storage_db_connections_open",
		"Established connections to the search index database, both in use and idle",
		[]string{"pool"}, nil)
	inUseConnsDesc = prometheus.NewDesc(
		"rekor_index_storage_db_connections_in_use",
		"Connections to the search index database currently in use",
		[]string{"pool"}, nil)
	idleConnsDesc = prometheus.NewDesc(
		"rekor_index_storage_db_connections_idle",
		"Idle connections to the search index database",
		[]string{"pool"}, nil)
	maxOpenConnsDesc = prometheus.NewDesc(
		"rekor_index_storage_db_connections_max_open",
		"Configured limit on open connections to the search index database, or 0 if unlimited",
		[]string{"pool"}, nil)
	waitCountDesc = prometheus.NewDesc(
		"rekor_index_storage_db_wait_count_total",
		"Total number of times a caller blocked waiting for a search index database connection",
		[]string{"pool"}, nil)
	waitDurationDesc = prometheus.NewDesc(
		"rekor_index_storage_db_wait_duration_seconds_total",
		"Total time callers spent blocked waiting for a search index database connection",
		[]string{"pool"}, nil)
)

// dbStatsCollector exports connection pool statistics for the search index
// read and write pools.
//
// collectors.NewDBStatsCollector covers the same DBStats fields, but hardcodes
// the go_sql_* metric prefix, which would leave these sitting apart from the
// rest of the rekor_index_storage_* family an operator correlates them against.
//
// One collector serves both pools because pool is a variable label here; two
// collectors sharing these descriptors would collide on registration.
type dbStatsCollector struct {
	readDB  *sqlx.DB
	writeDB *sqlx.DB
}

func (c *dbStatsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- openConnsDesc
	ch <- inUseConnsDesc
	ch <- idleConnsDesc
	ch <- maxOpenConnsDesc
	ch <- waitCountDesc
	ch <- waitDurationDesc
}

func (c *dbStatsCollector) Collect(ch chan<- prometheus.Metric) {
	c.collectPool(ch, poolRead, c.readDB)
	c.collectPool(ch, poolWrite, c.writeDB)
}

func (c *dbStatsCollector) collectPool(ch chan<- prometheus.Metric, role poolRole, db *sqlx.DB) {
	if db == nil {
		return
	}
	pool := role.String()
	stats := db.Stats()
	ch <- prometheus.MustNewConstMetric(openConnsDesc, prometheus.GaugeValue, float64(stats.OpenConnections), pool)
	ch <- prometheus.MustNewConstMetric(inUseConnsDesc, prometheus.GaugeValue, float64(stats.InUse), pool)
	ch <- prometheus.MustNewConstMetric(idleConnsDesc, prometheus.GaugeValue, float64(stats.Idle), pool)
	ch <- prometheus.MustNewConstMetric(maxOpenConnsDesc, prometheus.GaugeValue, float64(stats.MaxOpenConnections), pool)
	ch <- prometheus.MustNewConstMetric(waitCountDesc, prometheus.CounterValue, float64(stats.WaitCount), pool)
	ch <- prometheus.MustNewConstMetric(waitDurationDesc, prometheus.CounterValue, stats.WaitDuration.Seconds(), pool)
}
