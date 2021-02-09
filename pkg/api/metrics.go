package api

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	metricNewEntries = promauto.NewCounter(prometheus.CounterOpts{
		Name: "rekor_new_entries",
		Help: "The total number of new log entries",
	})
)
