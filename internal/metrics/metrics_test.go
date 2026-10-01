package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestNamespaceVulnerabilityGauges(t *testing.T) {
	SetNamespaceVulnerabilityGauges(map[string]map[string]int{
		"prod":    {"critical": 3, "high": 7},
		"staging": {"critical": 1},
	})

	if got := testutil.ToFloat64(VulnerabilityCount.WithLabelValues("prod", "critical")); got != 3 {
		t.Errorf("prod critical = %v, want 3", got)
	}
	if got := testutil.ToFloat64(VulnerabilityCount.WithLabelValues("prod", "high")); got != 7 {
		t.Errorf("prod high = %v, want 7", got)
	}
	if got := testutil.ToFloat64(VulnerabilityCount.WithLabelValues("staging", "critical")); got != 1 {
		t.Errorf("staging critical = %v, want 1", got)
	}

	// Recomputing replaces the whole picture: a namespace that disappears must
	// drop out, not linger at its old value.
	SetNamespaceVulnerabilityGauges(map[string]map[string]int{
		"prod": {"critical": 2},
	})
	if got := testutil.CollectAndCount(VulnerabilityCount); got != 1 {
		t.Errorf("series after recompute = %d, want 1 (only prod/critical)", got)
	}
	if got := testutil.ToFloat64(VulnerabilityCount.WithLabelValues("prod", "critical")); got != 2 {
		t.Errorf("prod critical after recompute = %v, want 2", got)
	}
}

func TestNamespaceReachabilityGauges(t *testing.T) {
	SetNamespaceReachabilityGauges(map[string]map[string]int{
		"prod": {"reachable": 18, "not_reachable": 170, "unknown": 2},
	})
	if got := testutil.ToFloat64(ReachabilityCount.WithLabelValues("prod", "reachable")); got != 18 {
		t.Errorf("prod reachable = %v, want 18", got)
	}
	if got := testutil.ToFloat64(ReachabilityCount.WithLabelValues("prod", "not_reachable")); got != 170 {
		t.Errorf("prod not_reachable = %v, want 170", got)
	}
	// Reset-on-set drops stale series.
	SetNamespaceReachabilityGauges(map[string]map[string]int{"prod": {"reachable": 1}})
	if got := testutil.CollectAndCount(ReachabilityCount); got != 1 {
		t.Errorf("series after recompute = %d, want 1", got)
	}
}

func TestReportPhasesAlwaysExported(t *testing.T) {
	SetReportPhases(map[string]int{"Failed": 2})
	if got := testutil.CollectAndCount(Reports); got != 4 {
		t.Errorf("want all 4 phases exported, got %d series", got)
	}
	if got := testutil.ToFloat64(Reports.WithLabelValues("Failed")); got != 2 {
		t.Errorf("Failed = %v", got)
	}
}

func TestSetVDB(t *testing.T) {
	SetVDB("vdb-2026-10-06", 3600)
	if got := testutil.ToFloat64(VDBInfo.WithLabelValues("vdb-2026-10-06")); got != 1 {
		t.Errorf("info = %v", got)
	}
	SetVDB("", 0)
	if got := testutil.CollectAndCount(VDBInfo); got != 0 {
		t.Errorf("unknown version must clear the info series, got %d", got)
	}
}
