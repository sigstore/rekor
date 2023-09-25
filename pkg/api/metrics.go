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
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"sigs.k8s.io/release-utils/version"
)

var (
	metricNewEntries = promauto.NewCounter(prometheus.CounterOpts{
		Name: "rekor_new_entries",
		Help: "The total number of new log entries",
	})

	metricPublishEvents = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rekor_publish_events",
		Help: "The status of publishing events to Pub/Sub",
	}, []string{"event", "content_type", "status"})

	MetricLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "rekor_api_latency",
		Help: "Api Latency on calls",
	}, []string{"path", "code"})

	MetricLatencySummary = promauto.NewSummaryVec(prometheus.SummaryOpts{
		Name: "rekor_api_latency_summary",
		Help: "Api Latency on calls",
	}, []string{"path", "code"})

	MetricRequestLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "rekor_latency_by_api",
		Help: "Api Latency (in ns) by path and method",
		Buckets: prometheus.ExponentialBucketsRange(
			float64(time.Millisecond),
			float64(4*time.Second),
			10),
	}, []string{"path", "method"})

	MetricRequestCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rekor_qps_by_api",
		Help: "Api QPS by path, method, and response code",
	}, []string{"path", "method", "code"})

	CheckpointPublishCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rekor_checkpoint_publish",
		Help: "Checkpoint publishing by shard and code",
	}, []string{"shard", "code"})

	_ = promauto.NewGaugeFunc(
		prometheus.GaugeOpts{
			Namespace: "rekor",
			Name:      "build_info",
			Help:      "A metric with a constant '1' value labeled by version, revision, branch, and goversion from which rekor was built.",
			ConstLabels: prometheus.Labels{
				"version":    version.GetVersionInfo().GitVersion,
				"revision":   version.GetVersionInfo().GitCommit,
				"build_date": version.GetVersionInfo().BuildDate,
				"goversion":  version.GetVersionInfo().GoVersion,
			},
		},
		func() float64 { return 1 },
	)
)
