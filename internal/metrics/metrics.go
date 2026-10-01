// Package metrics exposes operator-specific Prometheus metrics on the shared
// controller-runtime registry (scraped at the manager's metrics endpoint).
package metrics

import (
	"sync"

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

	// VulnerabilityCount is a gauge of current CVE counts aggregated per
	// namespace and severity across all reports (each report contributes the
	// summary of its latest successful scan). The label set is
	// deliberately low-cardinality (no image label) so it is safe to store in
	// a time-series database such as InfluxDB, where every unique tag
	// combination is a retained series. Per-image detail lives in the
	// DepScanReport resources instead.
	VulnerabilityCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "depscan_vulnerability_count",
			Help: "Current CVE count aggregated per namespace and severity.",
		},
		[]string{"namespace", "severity"},
	)

	// ReachabilityCount is a gauge of current CVE counts aggregated per
	// namespace and reachability state (reachable / not_reachable / unknown).
	// Low-cardinality (3 states), safe for time-series stores.
	ReachabilityCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "depscan_reachability_count",
			Help: "Current CVE count aggregated per namespace and reachability state.",
		},
		[]string{"namespace", "state"},
	)

	// Reports counts DepScanReports by phase (Pending, Scanning, Completed,
	// Failed), for backlog and failure alerts.
	Reports = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "depscan_reports",
			Help: "Number of DepScanReports by phase.",
		},
		[]string{"phase"},
	)

	// VDBAgeSeconds is the time since the current vulnerability database
	// version was primed; 0 while no version is known.
	VDBAgeSeconds = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "depscan_vdb_age_seconds",
			Help: "Seconds since the current vulnerability database version was primed.",
		},
	)

	// VDBInfo is 1 for the vulnerability database version scans use.
	VDBInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "depscan_vdb_info",
			Help: "The vulnerability database version scans use (value is always 1).",
		},
		[]string{"version"},
	)

	// VDBPrimeFailures counts failed VDB prime Jobs.
	VDBPrimeFailures = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "depscan_vdb_prime_failures_total",
			Help: "Number of failed vulnerability database prime Jobs.",
		},
	)
)

func init() {
	ctrlmetrics.Registry.MustRegister(ScansCompleted, ScanDurationSeconds, ReportsExported, VulnerabilityCount, ReachabilityCount,
		Reports, VDBAgeSeconds, VDBInfo, VDBPrimeFailures)
	// Export the scan outcomes from the start, so increase() over them is 0
	// rather than empty before the first scan finishes (the backlog alert
	// relies on that).
	for _, outcome := range []string{"completed", "failed"} {
		ScansCompleted.WithLabelValues(outcome)
	}
}

// gaugeMu serializes the replace-style setters below and guards the series
// they last published.
var (
	gaugeMu     sync.Mutex
	vulnSeries  = map[[2]string]bool{}
	reachSeries = map[[2]string]bool{}
	vdbVersion  string
)

// replaceSeries sets every (namespace, key) value of totals on vec and deletes
// the series published last time but absent now. Unlike Reset-then-Set, a
// concurrent scrape never sees the gauge empty. Caller holds gaugeMu.
func replaceSeries(vec *prometheus.GaugeVec, prev map[[2]string]bool, totals map[string]map[string]int) map[[2]string]bool {
	next := map[[2]string]bool{}
	for namespace, byKey := range totals {
		for key, n := range byKey {
			vec.WithLabelValues(namespace, key).Set(float64(n))
			next[[2]string{namespace, key}] = true
		}
	}
	for k := range prev {
		if !next[k] {
			vec.DeleteLabelValues(k[0], k[1])
		}
	}
	return next
}

// SetNamespaceVulnerabilityGauges replaces the vulnerability gauges with the
// supplied per-namespace, per-severity totals. Namespaces or severities no
// longer present (e.g. after a report is deleted) drop out instead of
// lingering at a stale value. Callers pass the full, recomputed picture, keyed
// by namespace then severity.
func SetNamespaceVulnerabilityGauges(totals map[string]map[string]int) {
	gaugeMu.Lock()
	defer gaugeMu.Unlock()
	vulnSeries = replaceSeries(VulnerabilityCount, vulnSeries, totals)
}

// SetNamespaceReachabilityGauges replaces the reachability gauges with the
// supplied per-namespace, per-state totals; stale series drop out. States are
// "reachable", "not_reachable", and "unknown".
func SetNamespaceReachabilityGauges(totals map[string]map[string]int) {
	gaugeMu.Lock()
	defer gaugeMu.Unlock()
	reachSeries = replaceSeries(ReachabilityCount, reachSeries, totals)
}

// SetReportPhases replaces the per-phase report counts. All phases are always
// exported (zero included) so alerts on e.g. Failed > 0 have a series.
func SetReportPhases(counts map[string]int) {
	for _, phase := range []string{"Pending", "Scanning", "Completed", "Failed"} {
		Reports.WithLabelValues(phase).Set(float64(counts[phase]))
	}
}

// SetVDB publishes the current VDB version and its age; an empty version
// removes the info series and sets the age to 0.
func SetVDB(version string, ageSeconds float64) {
	gaugeMu.Lock()
	defer gaugeMu.Unlock()
	if vdbVersion != "" && vdbVersion != version {
		VDBInfo.DeleteLabelValues(vdbVersion)
	}
	vdbVersion = version
	if version == "" {
		VDBAgeSeconds.Set(0)
		return
	}
	VDBInfo.WithLabelValues(version).Set(1)
	VDBAgeSeconds.Set(ageSeconds)
}
