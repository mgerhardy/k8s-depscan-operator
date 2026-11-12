package defectdojo

import (
	"encoding/json"
)

// MetricsToScoresForDefectDojo rewrites a dep-scan CSAF 2.1 document so the
// CVSS data it carries under vulnerabilities[].metrics[] is ALSO exposed under
// vulnerabilities[].scores[], the shape DefectDojo's CSAF parser reads.
//
// Why: dep-scan emits CSAF 2.1, which records CVSS in
//
//	vulnerabilities[].metrics[] = [{ "content": { "cvss_v3": {...} }, "products": [...] }]
//
// DefectDojo's CSAF parser (dojo/tools/csaf/parser.py, _scores_by_product) only
// reads the CSAF 2.0 shape:
//
//	vulnerabilities[].scores[] = [{ "cvss_v3": {...}, "products": [...] }]
//
// It never looks at metrics[], so every finding imports as Medium with no
// score even though the advisory carried a full CVSS vector and baseSeverity.
// This converts each metrics[] entry into the equivalent scores[] entry
// (content.<family> -> <family>, products copied verbatim), leaving every other
// field untouched.
//
// It only ADDS scores derived from metrics the finding already carries; a
// vulnerability that already has a scores[] entry is left untouched so a
// producer that emits both shapes is never double-counted. Input that is not
// valid JSON, or that needs no change, is returned byte-identical so a parsing
// quirk can never drop a report that would otherwise import.
func MetricsToScoresForDefectDojo(csaf []byte) []byte {
	if len(csaf) == 0 {
		return csaf
	}
	var doc map[string]any
	if err := json.Unmarshal(csaf, &doc); err != nil {
		return csaf
	}
	vulns, ok := doc["vulnerabilities"].([]any)
	if !ok {
		return csaf
	}

	changed := false
	for _, v := range vulns {
		vm, ok := v.(map[string]any)
		if !ok {
			continue
		}
		// Never override an existing scores[]: a producer that already emits
		// the 2.0 shape is authoritative.
		if existing, ok := vm["scores"].([]any); ok && len(existing) > 0 {
			continue
		}
		metrics, ok := vm["metrics"].([]any)
		if !ok || len(metrics) == 0 {
			continue
		}
		var scores []any
		for _, m := range metrics {
			mm, ok := m.(map[string]any)
			if !ok {
				continue
			}
			content, ok := mm["content"].(map[string]any)
			if !ok {
				continue
			}
			score := map[string]any{}
			for _, family := range []string{"cvss_v2", "cvss_v3", "cvss_v4"} {
				if body, ok := content[family]; ok {
					score[family] = body
				}
			}
			if len(score) == 0 {
				continue // a metric with no CVSS body yields no score
			}
			if products, ok := mm["products"]; ok {
				score["products"] = products
			}
			scores = append(scores, score)
		}
		if len(scores) == 0 {
			continue
		}
		vm["scores"] = scores
		changed = true
	}

	if !changed {
		return csaf
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return csaf
	}
	return out
}
