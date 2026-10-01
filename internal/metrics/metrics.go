// Package metrics exposes operator-specific Prometheus metrics on the shared
// controller-runtime registry (scraped at the manager's metrics endpoint).
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// ScansCompleted counts finished scans by outcome ("completed" / "failed").
	ScansCompleted = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "depscan_scans_completed_total",
			Help: "Number of image scans that finished, labeled by outcome.",
		},
		[]string{"outcome"},
	)

	// ScanDurationSeconds observes how long completed scans took, from Job
	// start to result ingestion.
	ScanDurationSeconds = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "depscan_scan_duration_seconds",
			Help:    "Duration of image scans from job start to ingestion.",
			Buckets: []float64{30, 60, 120, 300, 600, 1200, 2400, 4800},
		},
	)

	// ReportsExported counts DefectDojo export attempts by outcome.
	ReportsExported = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "depscan_reports_exported_total",
			Help: "Number of DefectDojo export attempts, labeled by outcome.",
		},
		[]string{"outcome"},
	)
)

func init() {
	ctrlmetrics.Registry.MustRegister(ScansCompleted, ScanDurationSeconds, ReportsExported)
}
