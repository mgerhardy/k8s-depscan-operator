package defectdojo

import (
	"encoding/json"
	"strings"
	"testing"
)

func cveOf(t *testing.T, csaf []byte, i int) string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(csaf, &doc); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	vulns, ok := doc["vulnerabilities"].([]any)
	if !ok {
		t.Fatalf("no vulnerabilities array in result")
	}
	return vulns[i].(map[string]any)["cve"].(string)
}

func TestSanitizeCSAF_SplitsCompositeCVEAtSlash(t *testing.T) {
	// The real value observed failing the reimport (51 chars): advisory id
	// joined to a package URL. Expect the advisory id alone.
	in := []byte(`{"vulnerabilities":[{"cve":"GO-2026-5932/pkg:golang/golang.org/x/crypto@v0.55.0","title":"x"}]}`)
	out := SanitizeCSAFForDefectDojo(in)
	if got := cveOf(t, out, 0); got != "GO-2026-5932" {
		t.Errorf("cve = %q, want %q", got, "GO-2026-5932")
	}
}

func TestSanitizeCSAF_LeavesShortCVEUntouched(t *testing.T) {
	in := []byte(`{"vulnerabilities":[{"cve":"CVE-2023-48795"}]}`)
	out := SanitizeCSAFForDefectDojo(in)
	// Unchanged input must be returned byte-identical (no needless re-marshal).
	if string(out) != string(in) {
		t.Errorf("short cve should be untouched;\n got %s\nwant %s", out, in)
	}
}

func TestSanitizeCSAF_HardTruncatesWhenNoUsableSlash(t *testing.T) {
	// A single token with no "/" that is over the limit: hard-truncate to 50.
	long := strings.Repeat("A", 70)
	in := []byte(`{"vulnerabilities":[{"cve":"` + long + `"}]}`)
	out := SanitizeCSAFForDefectDojo(in)
	got := cveOf(t, out, 0)
	if len(got) != maxCVELen || got != long[:maxCVELen] {
		t.Errorf("cve = %q (len %d), want first %d chars", got, len(got), maxCVELen)
	}
}

func TestSanitizeCSAF_SlashPrefixStillTooLongFallsBackToTruncate(t *testing.T) {
	// Advisory part before "/" is itself > 50: cannot use it, hard-truncate
	// the whole value instead.
	pfx := strings.Repeat("B", 60)
	in := []byte(`{"vulnerabilities":[{"cve":"` + pfx + `/pkg:x"}]}`)
	out := SanitizeCSAFForDefectDojo(in)
	got := cveOf(t, out, 0)
	if len(got) != maxCVELen {
		t.Errorf("cve len = %d, want %d", len(got), maxCVELen)
	}
}

func TestSanitizeCSAF_CapsEveryOverlongEntry(t *testing.T) {
	in := []byte(`{"vulnerabilities":[` +
		`{"cve":"GO-2026-5932/pkg:golang/golang.org/x/crypto@v0.55.0"},` +
		`{"cve":"CVE-2023-1"},` +
		`{"cve":"GHSA-aaaa-bbbb-cccc/pkg:npm/some/very/long/package@1.2.3.4.5.6"}]}`)
	out := SanitizeCSAFForDefectDojo(in)
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	for i, v := range doc["vulnerabilities"].([]any) {
		cve := v.(map[string]any)["cve"].(string)
		if len(cve) > maxCVELen {
			t.Errorf("vuln[%d] cve still too long: %q (%d)", i, cve, len(cve))
		}
	}
}

func TestSanitizeCSAF_InvalidJSONReturnedUnchanged(t *testing.T) {
	in := []byte(`not json`)
	if got := SanitizeCSAFForDefectDojo(in); string(got) != string(in) {
		t.Errorf("invalid JSON should be returned as-is, got %q", got)
	}
	if got := SanitizeCSAFForDefectDojo(nil); got != nil {
		t.Errorf("nil should be returned as nil, got %q", got)
	}
}

func TestSanitizeCSAF_CapsOverlongIdsText(t *testing.T) {
	// DefectDojo falls back to vulnerabilities[].ids[].text for the identifier
	// when "cve" is empty; an over-long value there must also be capped.
	in := []byte(`{"vulnerabilities":[{"cve":"","ids":[` +
		`{"system_name":"GitHub","text":"GHSA-xxxx-yyyy-zzzz/pkg:golang/golang.org/x/net@v0.44.0"},` +
		`{"system_name":"CVE","text":"CVE-2025-1"}]}]}`)
	out := SanitizeCSAFForDefectDojo(in)
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	ids := doc["vulnerabilities"].([]any)[0].(map[string]any)["ids"].([]any)
	first := ids[0].(map[string]any)["text"].(string)
	if first != "GHSA-xxxx-yyyy-zzzz" {
		t.Errorf("ids[0].text = %q, want %q", first, "GHSA-xxxx-yyyy-zzzz")
	}
	if second := ids[1].(map[string]any)["text"].(string); second != "CVE-2025-1" {
		t.Errorf("ids[1].text = %q, want it untouched", second)
	}
}

func TestSanitizeCSAF_CapsBothCVEAndIdsText(t *testing.T) {
	in := []byte(`{"vulnerabilities":[{` +
		`"cve":"GO-2026-5932/pkg:golang/golang.org/x/crypto@v0.55.0",` +
		`"ids":[{"text":"` + strings.Repeat("Z", 70) + `"}]}]}`)
	res := SanitizeCSAFForDefectDojo(in)
	var doc map[string]any
	if err := json.Unmarshal(res, &doc); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	v := doc["vulnerabilities"].([]any)[0].(map[string]any)
	if cve := v["cve"].(string); len(cve) > maxCVELen {
		t.Errorf("cve still too long: %q", cve)
	}
	txt := v["ids"].([]any)[0].(map[string]any)["text"].(string)
	if len(txt) != maxCVELen {
		t.Errorf("ids text len = %d, want %d", len(txt), maxCVELen)
	}
}
