package scan

import (
	"testing"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
)

func TestParseCSAFReachability(t *testing.T) {
	csaf := `{"vulnerabilities":[
	  {"cve":"CVE-R","product_status":{"known_affected":["p1"]}},
	  {"cve":"CVE-N","product_status":{"known_not_affected":["p2"]}},
	  {"cve":"CVE-U","product_status":{"under_investigation":["p3"]}}
	]}`
	got := parseCSAFReachability([]byte(csaf))
	if !got.analyzed {
		t.Error("analyzed should be true when a decided status is present")
	}
	want := map[string]depscanv1alpha1.Reachability{
		"CVE-R": depscanv1alpha1.ReachabilityReachable,
		"CVE-N": depscanv1alpha1.ReachabilityNotReachable,
		"CVE-U": depscanv1alpha1.ReachabilityUnknown,
	}
	for cve, w := range want {
		if got.byCVE[cve] != w {
			t.Errorf("%s = %q, want %q", cve, got.byCVE[cve], w)
		}
	}
}

func TestParseCSAFReachability_NotAnalyzed(t *testing.T) {
	// Only under_investigation (or empty) => analysis did not run.
	csaf := `{"vulnerabilities":[{"cve":"CVE-X","product_status":{"under_investigation":["p"]}}]}`
	got := parseCSAFReachability([]byte(csaf))
	if got.analyzed {
		t.Error("analyzed should be false when nothing is decided")
	}
	if got.byCVE["CVE-X"] != depscanv1alpha1.ReachabilityUnknown {
		t.Errorf("CVE-X should be unknown")
	}

	// Empty document.
	if parseCSAFReachability([]byte("{}")).analyzed {
		t.Error("empty CSAF should not be analyzed")
	}
	if parseCSAFReachability(nil).analyzed {
		t.Error("nil CSAF should not be analyzed")
	}
}

func TestParseReports_MergesCSAFReachability(t *testing.T) {
	vdr := `{"vulnerabilities":[
	  {"id":"CVE-R","affects":[{"ref":"pkg:maven/g/a@1"}],"ratings":[{"severity":"high"}]},
	  {"id":"CVE-N","affects":[{"ref":"pkg:maven/g/b@1"}],"ratings":[{"severity":"high"}]},
	  {"id":"CVE-U","affects":[{"ref":"pkg:apk/alpine/c@1"}],"ratings":[{"severity":"low"}]}
	]}`
	csaf := `{"vulnerabilities":[
	  {"cve":"CVE-R","product_status":{"known_affected":["p1"]}},
	  {"cve":"CVE-N","product_status":{"known_not_affected":["p2"]},"flags":[{"label":"vulnerable_code_not_in_execute_path","product_ids":["p2"]}]}
	]}`
	res, err := ParseReports([]byte(vdr), []byte(csaf))
	if err != nil {
		t.Fatal(err)
	}
	if !res.ReachabilityAnalyzed {
		t.Error("ReachabilityAnalyzed should be true")
	}
	byID := map[string]depscanv1alpha1.Reachability{}
	for _, v := range res.Vulnerabilities {
		byID[v.VulnerabilityID] = v.Reachability
	}
	if byID["CVE-R"] != depscanv1alpha1.ReachabilityReachable {
		t.Errorf("CVE-R = %q, want reachable", byID["CVE-R"])
	}
	if byID["CVE-N"] != depscanv1alpha1.ReachabilityNotReachable {
		t.Errorf("CVE-N = %q, want not-reachable", byID["CVE-N"])
	}
	// CVE-U is absent from CSAF => stays unknown (not analyzed for it).
	if byID["CVE-U"] != depscanv1alpha1.ReachabilityUnknown {
		t.Errorf("CVE-U = %q, want unknown", byID["CVE-U"])
	}
	if res.Summary.ReachableCount != 1 || res.Summary.NotReachableCount != 1 || res.Summary.UnknownReachabilityCount != 1 {
		t.Errorf("counts: reachable=%d not=%d unknown=%d, want 1/1/1",
			res.Summary.ReachableCount, res.Summary.NotReachableCount, res.Summary.UnknownReachabilityCount)
	}
}

func TestParseReports_NoCSAFStaysUnknown(t *testing.T) {
	vdr := `{"vulnerabilities":[{"id":"CVE-1","affects":[{"ref":"pkg:apk/alpine/x@1"}],"ratings":[{"severity":"high"}]}]}`
	res, err := ParseReports([]byte(vdr), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.ReachabilityAnalyzed {
		t.Error("no CSAF => not analyzed")
	}
	if res.Summary.UnknownReachabilityCount != 1 {
		t.Errorf("unknownReachability = %d, want 1", res.Summary.UnknownReachabilityCount)
	}
}
