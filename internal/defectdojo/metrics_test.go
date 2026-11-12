package defectdojo

import (
	"encoding/json"
	"testing"
)

// firstScore returns vulnerabilities[i].scores[0] as a map, or nil.
func firstScore(t *testing.T, csaf []byte, i int) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(csaf, &doc); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	vulns := doc["vulnerabilities"].([]any)
	vm := vulns[i].(map[string]any)
	scores, ok := vm["scores"].([]any)
	if !ok || len(scores) == 0 {
		return nil
	}
	return scores[0].(map[string]any)
}

func TestMetricsToScores_MirrorsCVSSv3(t *testing.T) {
	// The real dep-scan CSAF 2.1 shape: CVSS lives under metrics[].content.
	in := []byte(`{"vulnerabilities":[{
	  "cve":"CVE-2026-1",
	  "product_status":{"under_investigation":["p1"]},
	  "metrics":[{"content":{"cvss_v3":{"version":"3.1","baseSeverity":"CRITICAL","baseScore":9.1}},"products":["p1"]}]
	}]}`)
	out := MetricsToScoresForDefectDojo(in)

	s := firstScore(t, out, 0)
	if s == nil {
		t.Fatal("expected a scores[] entry mirrored from metrics[]")
	}
	cvss, ok := s["cvss_v3"].(map[string]any)
	if !ok {
		t.Fatalf("scores[0].cvss_v3 missing: %v", s)
	}
	if cvss["baseSeverity"] != "CRITICAL" || cvss["baseScore"] != 9.1 {
		t.Errorf("cvss_v3 = %v, want baseSeverity CRITICAL / baseScore 9.1", cvss)
	}
	prods, ok := s["products"].([]any)
	if !ok || len(prods) != 1 || prods[0] != "p1" {
		t.Errorf("products = %v, want [p1]", s["products"])
	}
}

func TestMetricsToScores_CopiesProductsVerbatim(t *testing.T) {
	// products carry full purls; they must be copied unchanged so DefectDojo
	// attaches the score to the right product.
	purl := "pkg:rpm/redhat/libxml2@2.9.13-14.el9_8.5?arch=x86_64&distro=rhel-9.8"
	in := []byte(`{"vulnerabilities":[{
	  "cve":"CVE-2026-2",
	  "metrics":[{"content":{"cvss_v3":{"baseSeverity":"HIGH"}},"products":["` + purl + `"]}]
	}]}`)
	s := firstScore(t, MetricsToScoresForDefectDojo(in), 0)
	prods := s["products"].([]any)
	if len(prods) != 1 || prods[0] != purl {
		t.Errorf("products = %v, want [%s]", prods, purl)
	}
}

func TestMetricsToScores_KeepsAllCVSSFamilies(t *testing.T) {
	in := []byte(`{"vulnerabilities":[{
	  "cve":"CVE-2026-3",
	  "metrics":[{"content":{"cvss_v2":{"baseScore":5.0},"cvss_v3":{"baseSeverity":"MEDIUM"},"cvss_v4":{"baseScore":6.0}},"products":["p1"]}]
	}]}`)
	s := firstScore(t, MetricsToScoresForDefectDojo(in), 0)
	for _, fam := range []string{"cvss_v2", "cvss_v3", "cvss_v4"} {
		if _, ok := s[fam]; !ok {
			t.Errorf("score missing family %s: %v", fam, s)
		}
	}
}

func TestMetricsToScores_DoesNotOverrideExistingScores(t *testing.T) {
	// A producer that already emits scores[] is authoritative; metrics[] is
	// ignored and the document is returned byte-identical.
	in := []byte(`{"vulnerabilities":[{
	  "cve":"CVE-2026-4",
	  "scores":[{"products":["p1"],"cvss_v3":{"baseSeverity":"LOW"}}],
	  "metrics":[{"content":{"cvss_v3":{"baseSeverity":"CRITICAL"}},"products":["p1"]}]
	}]}`)
	if out := MetricsToScoresForDefectDojo(in); string(out) != string(in) {
		t.Errorf("existing scores[] must be untouched;\n got %s\nwant %s", out, in)
	}
}

func TestMetricsToScores_NoMetricsIsUnchanged(t *testing.T) {
	in := []byte(`{"vulnerabilities":[{"cve":"CVE-2026-5","product_status":{"under_investigation":["p1"]}}]}`)
	if out := MetricsToScoresForDefectDojo(in); string(out) != string(in) {
		t.Errorf("no metrics should leave the document unchanged, got %s", out)
	}
}

func TestMetricsToScores_MetricWithoutCVSSBodyProducesNoScore(t *testing.T) {
	in := []byte(`{"vulnerabilities":[{"cve":"CVE-2026-6","metrics":[{"content":{"other":{}},"products":["p1"]}]}]}`)
	if out := MetricsToScoresForDefectDojo(in); string(out) != string(in) {
		t.Errorf("a metric with no CVSS body should produce no score, got %s", out)
	}
}

func TestMetricsToScores_MultipleMetricsBecomeMultipleScores(t *testing.T) {
	// A CVE scored differently per product: each metrics[] entry becomes its
	// own scores[] entry.
	in := []byte(`{"vulnerabilities":[{
	  "cve":"CVE-2026-7",
	  "metrics":[
	    {"content":{"cvss_v3":{"baseSeverity":"HIGH"}},"products":["p1"]},
	    {"content":{"cvss_v3":{"baseSeverity":"LOW"}},"products":["p2"]}]
	}]}`)
	var doc map[string]any
	_ = json.Unmarshal(MetricsToScoresForDefectDojo(in), &doc)
	scores := doc["vulnerabilities"].([]any)[0].(map[string]any)["scores"].([]any)
	if len(scores) != 2 {
		t.Fatalf("want 2 scores, got %d", len(scores))
	}
}

func TestMetricsToScores_InvalidOrEmptyReturnedUnchanged(t *testing.T) {
	if got := MetricsToScoresForDefectDojo([]byte(`not json`)); string(got) != "not json" {
		t.Errorf("invalid JSON should be returned as-is, got %q", got)
	}
	if got := MetricsToScoresForDefectDojo(nil); got != nil {
		t.Errorf("nil should be returned as nil, got %q", got)
	}
}
