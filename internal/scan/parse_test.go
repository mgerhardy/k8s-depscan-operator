package scan

import (
	"testing"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
)

const sampleVDR = `{
  "bomFormat": "CycloneDX",
  "vulnerabilities": [
    {
      "id": "CVE-2024-0001",
      "bom-ref": "pkg:deb/debian/openssl@1.1.1n?arch=amd64",
      "ratings": [
        {"severity": "critical", "score": 9.8, "method": "CVSSv31"},
        {"severity": "high", "score": 7.5, "method": "CVSSv2"}
      ],
      "affects": [{"ref": "pkg:deb/debian/openssl@1.1.1n?arch=amd64"}],
      "source": {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"},
      "properties": [
        {"name": "depscan:insights", "value": "x"},
        {"name": "depscan:reachability", "value": "reachable"},
        {"name": "depscan:fixed_version", "value": "1.1.1t"}
      ]
    },
    {
      "id": "CVE-2024-0002",
      "affects": [{"ref": "pkg:npm/lodash@4.17.11"}],
      "ratings": [{"severity": "medium", "score": 5.3}],
      "properties": [{"name": "depscan:reachability", "value": "not-reachable"}]
    },
    {
      "id": "CVE-2024-0003",
      "affects": [{"ref": "pkg:npm/leftpad@1.0.0"}],
      "ratings": [{"severity": "low"}]
    }
  ]
}`

func TestParseVDR(t *testing.T) {
	res, err := ParseVDR([]byte(sampleVDR))
	if err != nil {
		t.Fatalf("ParseVDR returned error: %v", err)
	}

	if got, want := len(res.Vulnerabilities), 3; got != want {
		t.Fatalf("vulnerability count = %d, want %d", got, want)
	}

	// Sorted by severity desc: critical first.
	first := res.Vulnerabilities[0]
	if first.VulnerabilityID != "CVE-2024-0001" {
		t.Errorf("first vuln = %s, want CVE-2024-0001", first.VulnerabilityID)
	}
	if first.Severity != depscanv1alpha1.SeverityCritical {
		t.Errorf("severity = %s, want CRITICAL", first.Severity)
	}
	if first.Score != "9.8" {
		t.Errorf("score = %q, want 9.8", first.Score)
	}
	if first.Resource != "openssl" {
		t.Errorf("resource = %q, want openssl", first.Resource)
	}
	if first.InstalledVersion != "1.1.1n" {
		t.Errorf("installedVersion = %q, want 1.1.1n", first.InstalledVersion)
	}
	if first.FixedVersion != "1.1.1t" {
		t.Errorf("fixedVersion = %q, want 1.1.1t", first.FixedVersion)
	}
	if first.Reachability != depscanv1alpha1.ReachabilityReachable {
		t.Errorf("reachability = %s, want reachable", first.Reachability)
	}
	if first.PrimaryLink == "" {
		t.Errorf("primaryLink should be set from source.url")
	}

	// Summary checks.
	s := res.Summary
	if s.CriticalCount != 1 || s.MediumCount != 1 || s.LowCount != 1 {
		t.Errorf("summary counts unexpected: %+v", s)
	}
	if s.ReachableCount != 1 {
		t.Errorf("reachableCount = %d, want 1", s.ReachableCount)
	}
}

func TestPackageFromPURL(t *testing.T) {
	cases := map[string]struct{ name, version string }{
		"pkg:deb/debian/openssl@1.1.1n-0+deb11u5?arch=amd64": {"openssl", "1.1.1n-0+deb11u5"},
		"pkg:npm/lodash@4.17.11":                             {"lodash", "4.17.11"},
		"pkg:maven/org.apache/commons@1.0":                   {"commons", "1.0"},
		"":                                                   {"", ""},
	}
	for purl, want := range cases {
		name, version := packageFromPURL(purl)
		if name != want.name || version != want.version {
			t.Errorf("packageFromPURL(%q) = (%q,%q), want (%q,%q)", purl, name, version, want.name, want.version)
		}
	}
}

func TestReachabilityAnalysisStates(t *testing.T) {
	// CycloneDX analysis.state is a VEX adjudication state, not a reachability
	// verdict. dep-scan defaults OS-package findings to "in_triage", which must
	// NOT be reported as reachable.
	doc := `{"vulnerabilities":[
	  {"id":"CVE-A","affects":[{"ref":"pkg:apk/alpine/libxml2@2.13.9"}],"ratings":[{"severity":"low"}],"analysis":{"state":"in_triage"}},
	  {"id":"CVE-B","affects":[{"ref":"pkg:apk/alpine/foo@1.0"}],"ratings":[{"severity":"low"}],"analysis":{"state":"not_affected"}},
	  {"id":"CVE-C","affects":[{"ref":"pkg:apk/alpine/bar@1.0"}],"ratings":[{"severity":"low"}],"analysis":{"state":"exploitable"}},
	  {"id":"CVE-D","affects":[{"ref":"pkg:npm/app@1.0"}],"ratings":[{"severity":"high"}],"properties":[{"name":"depscan:reachability","value":"reachable"}]}
	]}`
	res, err := ParseVDR([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]depscanv1alpha1.Reachability{
		"CVE-A": depscanv1alpha1.ReachabilityUnknown,      // in_triage -> unknown
		"CVE-B": depscanv1alpha1.ReachabilityNotReachable, // not_affected -> not-reachable
		"CVE-C": depscanv1alpha1.ReachabilityUnknown,      // exploitable (VEX) is not reachability
		"CVE-D": depscanv1alpha1.ReachabilityReachable,    // explicit property wins
	}
	got := map[string]depscanv1alpha1.Reachability{}
	for _, v := range res.Vulnerabilities {
		got[v.VulnerabilityID] = v.Reachability
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s reachability = %q, want %q", id, got[id], w)
		}
	}
	if res.Summary.ReachableCount != 1 {
		t.Errorf("reachableCount = %d, want 1 (only the explicit property)", res.Summary.ReachableCount)
	}
}

func TestNormalizeSeverity(t *testing.T) {
	if normalizeSeverity("moderate") != depscanv1alpha1.SeverityMedium {
		t.Errorf("moderate should map to MEDIUM")
	}
	if normalizeSeverity("weird") != depscanv1alpha1.SeverityUnknown {
		t.Errorf("unknown input should map to UNKNOWN")
	}
}
