package defectdojo

import (
	"encoding/json"
	"testing"
)

// scoreCVSS returns the cvss_v3 body of vulnerabilities[i].scores[0], or nil if
// the vulnerability has no scores.
func scoreCVSS(t *testing.T, csaf []byte, i int) map[string]any {
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
	return scores[0].(map[string]any)["cvss_v3"].(map[string]any)
}

func TestEnrich_BackfillsSeverityFromVDR(t *testing.T) {
	vdr := []byte(`{"vulnerabilities":[
	  {"id":"CVE-2026-1","ratings":[{"severity":"critical","score":9.8}]}]}`)
	// CSAF finding with a product_status but no scores -- the OS-advisory case.
	csaf := []byte(`{"vulnerabilities":[
	  {"cve":"CVE-2026-1","product_status":{"under_investigation":["p1"]}}]}`)

	out := EnrichCSAFScoresFromVDR(csaf, vdr)
	cvss := scoreCVSS(t, out, 0)
	if cvss == nil {
		t.Fatal("expected a backfilled cvss_v3 score, got none")
	}
	if cvss["baseSeverity"] != "CRITICAL" {
		t.Errorf("baseSeverity = %v, want CRITICAL", cvss["baseSeverity"])
	}
	if cvss["baseScore"] != 9.8 {
		t.Errorf("baseScore = %v, want 9.8", cvss["baseScore"])
	}
	// products must target the product_status ids so DefectDojo attaches the
	// score to the finding.
	var doc map[string]any
	_ = json.Unmarshal(out, &doc)
	sc := doc["vulnerabilities"].([]any)[0].(map[string]any)["scores"].([]any)[0].(map[string]any)
	prods := sc["products"].([]any)
	if len(prods) != 1 || prods[0] != "p1" {
		t.Errorf("products = %v, want [p1]", prods)
	}
}

func TestEnrich_SeverityWithoutNumericScore(t *testing.T) {
	// The common distro case: a qualitative severity and no CVSS score. The
	// backfill must still emit baseSeverity (DefectDojo maps it) and omit
	// baseScore rather than inventing one.
	vdr := []byte(`{"vulnerabilities":[{"id":"CVE-2026-2","ratings":[{"severity":"high"}]}]}`)
	csaf := []byte(`{"vulnerabilities":[{"cve":"CVE-2026-2","product_status":{"under_investigation":["p1"]}}]}`)

	cvss := scoreCVSS(t, EnrichCSAFScoresFromVDR(csaf, vdr), 0)
	if cvss == nil {
		t.Fatal("expected a backfilled score")
	}
	if cvss["baseSeverity"] != "HIGH" {
		t.Errorf("baseSeverity = %v, want HIGH", cvss["baseSeverity"])
	}
	if _, present := cvss["baseScore"]; present {
		t.Errorf("baseScore should be absent when the VDR has no numeric score, got %v", cvss["baseScore"])
	}
}

func TestEnrich_StringScoreFromVDR(t *testing.T) {
	// dep-scan v6.3.x quotes the score; the backfill must accept the string.
	vdr := []byte(`{"vulnerabilities":[{"id":"CVE-2026-3","ratings":[{"severity":"medium","score":"5.3"}]}]}`)
	csaf := []byte(`{"vulnerabilities":[{"cve":"CVE-2026-3","product_status":{"under_investigation":["p1"]}}]}`)

	cvss := scoreCVSS(t, EnrichCSAFScoresFromVDR(csaf, vdr), 0)
	if cvss["baseScore"] != 5.3 {
		t.Errorf("baseScore = %v, want 5.3", cvss["baseScore"])
	}
}

func TestEnrich_DoesNotOverrideExistingScore(t *testing.T) {
	vdr := []byte(`{"vulnerabilities":[{"id":"CVE-2026-4","ratings":[{"severity":"low"}]}]}`)
	// CSAF already has a real cvss_v3 -- it must be left byte-identical.
	csaf := []byte(`{"vulnerabilities":[{"cve":"CVE-2026-4","product_status":{"known_affected":["p1"]},` +
		`"scores":[{"products":["p1"],"cvss_v3":{"baseSeverity":"CRITICAL","baseScore":9.8}}]}]}`)

	out := EnrichCSAFScoresFromVDR(csaf, vdr)
	if string(out) != string(csaf) {
		t.Errorf("existing score must be untouched;\n got %s\nwant %s", out, csaf)
	}
}

func TestEnrich_MatchesByIdsTextWhenCVEEmpty(t *testing.T) {
	// DefectDojo keys on ids[].text when cve is empty; the backfill must match
	// the VDR id the same way.
	vdr := []byte(`{"vulnerabilities":[{"id":"DLA-4485-1","ratings":[{"severity":"high"}]}]}`)
	csaf := []byte(`{"vulnerabilities":[{"cve":"","ids":[{"system_name":"Debian","text":"DLA-4485-1"}],` +
		`"product_status":{"under_investigation":["p1"]}}]}`)

	cvss := scoreCVSS(t, EnrichCSAFScoresFromVDR(csaf, vdr), 0)
	if cvss == nil || cvss["baseSeverity"] != "HIGH" {
		t.Errorf("expected HIGH backfilled via ids[].text, got %v", cvss)
	}
}

func TestEnrich_NoProductStatusIsSkipped(t *testing.T) {
	// Without product_status there are no product_ids to target, so a score
	// could not be attached; the finding is left unchanged.
	vdr := []byte(`{"vulnerabilities":[{"id":"CVE-2026-5","ratings":[{"severity":"critical"}]}]}`)
	csaf := []byte(`{"vulnerabilities":[{"cve":"CVE-2026-5"}]}`)

	if out := EnrichCSAFScoresFromVDR(csaf, vdr); string(out) != string(csaf) {
		t.Errorf("finding without product_status should be untouched, got %s", out)
	}
}

func TestEnrich_UnknownSeverityIsSkipped(t *testing.T) {
	vdr := []byte(`{"vulnerabilities":[{"id":"CVE-2026-6","ratings":[{"severity":"weird"}]}]}`)
	csaf := []byte(`{"vulnerabilities":[{"cve":"CVE-2026-6","product_status":{"under_investigation":["p1"]}}]}`)

	if out := EnrichCSAFScoresFromVDR(csaf, vdr); string(out) != string(csaf) {
		t.Errorf("unmappable severity should produce no score, got %s", out)
	}
}

func TestEnrich_TopRatingWins(t *testing.T) {
	// Multiple ratings: the highest severity is carried across.
	vdr := []byte(`{"vulnerabilities":[{"id":"CVE-2026-7","ratings":[` +
		`{"severity":"low","score":3.1},{"severity":"critical","score":9.1},{"severity":"medium"}]}]}`)
	csaf := []byte(`{"vulnerabilities":[{"cve":"CVE-2026-7","product_status":{"under_investigation":["p1"]}}]}`)

	cvss := scoreCVSS(t, EnrichCSAFScoresFromVDR(csaf, vdr), 0)
	if cvss["baseSeverity"] != "CRITICAL" || cvss["baseScore"] != 9.1 {
		t.Errorf("top rating not chosen: got %v", cvss)
	}
}

func TestEnrich_NoMatchInVDRLeavesUnchanged(t *testing.T) {
	vdr := []byte(`{"vulnerabilities":[{"id":"CVE-OTHER","ratings":[{"severity":"critical"}]}]}`)
	csaf := []byte(`{"vulnerabilities":[{"cve":"CVE-2026-8","product_status":{"under_investigation":["p1"]}}]}`)

	if out := EnrichCSAFScoresFromVDR(csaf, vdr); string(out) != string(csaf) {
		t.Errorf("no VDR match should leave the CSAF unchanged, got %s", out)
	}
}

func TestEnrich_InvalidOrEmptyInputReturnedUnchanged(t *testing.T) {
	csaf := []byte(`{"vulnerabilities":[{"cve":"CVE-2026-9","product_status":{"under_investigation":["p1"]}}]}`)
	if got := EnrichCSAFScoresFromVDR(csaf, []byte(`not json`)); string(got) != string(csaf) {
		t.Errorf("invalid VDR should leave CSAF unchanged")
	}
	if got := EnrichCSAFScoresFromVDR([]byte(`not json`), []byte(`{"vulnerabilities":[]}`)); string(got) != "not json" {
		t.Errorf("invalid CSAF should be returned as-is")
	}
	if got := EnrichCSAFScoresFromVDR(nil, nil); got != nil {
		t.Errorf("nil should be returned as nil")
	}
	if got := EnrichCSAFScoresFromVDR(csaf, nil); string(got) != string(csaf) {
		t.Errorf("empty VDR should leave CSAF unchanged")
	}
}
