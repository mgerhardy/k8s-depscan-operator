package defectdojo

import (
	"encoding/json"
	"strconv"
	"strings"
)

// EnrichCSAFScoresFromVDR backfills a CVSS severity onto CSAF vulnerabilities
// that lack one, using the severity dep-scan already recorded in the matching
// VDR document.
//
// Why this is needed: DefectDojo's CSAF parser derives a finding's severity
// solely from vulnerabilities[].scores[].cvss_v3 (baseSeverity, else baseScore
// banded). When dep-scan emits a vulnerability with no cvss_v3 score body --
// which happens for the many OS/distro advisories (RHEL/SUSE/Alpine RPMs) that
// carry only a qualitative severity and no CVSS vector -- the parser falls back
// to "Medium" with an empty score. The result is that genuinely critical/high
// findings all import as Medium.
//
// dep-scan DOES know the severity for those findings: it is in the VDR's
// ratings[].severity (the same data the operator uses for the CRD summary's
// criticalCount/highCount). This function carries that severity across into the
// CSAF the operator uploads, so DefectDojo classifies the finding correctly.
//
// It only ADDS a score where none exists; a vulnerability that already carries
// a cvss_v3 score is left untouched, so a real CVSS vector always wins over the
// synthesized qualitative one. Input that is not valid JSON, or that needs no
// change, is returned byte-identical so a parsing quirk can never drop a report
// that would otherwise import.
func EnrichCSAFScoresFromVDR(csaf, vdr []byte) []byte {
	if len(csaf) == 0 || len(vdr) == 0 {
		return csaf
	}

	sevByID := vdrSeverityByID(vdr)
	if len(sevByID) == 0 {
		return csaf
	}

	var doc map[string]any
	if err := json.Unmarshal(csaf, &doc); err != nil {
		return csaf // not parseable as an object; leave it to the server
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
		if hasCVSSv3Score(vm) {
			continue // a real score is present; never override it
		}
		id := csafIdentifier(vm)
		if id == "" {
			continue
		}
		rating, ok := sevByID[id]
		if !ok || rating.baseSeverity == "" {
			continue
		}
		productIDs := productIDsOf(vm)
		if len(productIDs) == 0 {
			continue
		}
		cvss := map[string]any{
			"version":      "3.1",
			"baseSeverity": rating.baseSeverity,
		}
		if rating.baseScore != nil {
			cvss["baseScore"] = *rating.baseScore
		}
		score := map[string]any{
			"products": productIDs,
			"cvss_v3":  cvss,
		}
		vm["scores"] = append(existingScores(vm), score)
		changed = true
	}

	if !changed {
		return csaf
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return csaf // re-marshal failed; send the original rather than nothing
	}
	return out
}

// vdrRatingValue is the severity picture carried across from one VDR
// vulnerability: an upper-case CVSS v3 qualitative label and, when dep-scan
// supplied it, the numeric base score.
type vdrRatingValue struct {
	baseSeverity string
	baseScore    *float64
}

// vdrSeverityByID indexes the highest-severity rating of each VDR vulnerability
// by its identifier (the "id", which is a CVE or an advisory id). Only ratings
// with a mappable severity are kept.
func vdrSeverityByID(vdr []byte) map[string]vdrRatingValue {
	var doc struct {
		Vulnerabilities []struct {
			ID      string `json:"id"`
			Ratings []struct {
				Severity string `json:"severity"`
				Score    any    `json:"score"`
			} `json:"ratings"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(vdr, &doc); err != nil {
		return nil
	}

	out := make(map[string]vdrRatingValue, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		id := strings.TrimSpace(v.ID)
		if id == "" {
			continue
		}
		bestRank := -1
		var best vdrRatingValue
		for _, r := range v.Ratings {
			label := normalizeCVSSSeverity(r.Severity)
			if label == "" {
				continue
			}
			if rank := cvssSeverityRank(label); rank > bestRank {
				bestRank = rank
				best = vdrRatingValue{baseSeverity: label, baseScore: flexScore(r.Score)}
			}
		}
		if bestRank >= 0 {
			out[id] = best
		}
	}
	return out
}

// flexScore reads a CVSS score that dep-scan may emit as a JSON number or a
// quoted string, returning nil for an absent, null or non-numeric value.
func flexScore(v any) *float64 {
	switch n := v.(type) {
	case float64:
		return &n
	case string:
		s := strings.TrimSpace(n)
		if s == "" {
			return nil
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return nil
		}
		return &f
	default:
		return nil
	}
}

// csafIdentifier returns the identifier DefectDojo's CSAF parser uses to key a
// finding: the "cve" when present, else the first ids[].text. It mirrors the
// parser's own _identifier() precedence so a backfilled score matches the
// finding it was derived for.
func csafIdentifier(vm map[string]any) string {
	if cve, ok := vm["cve"].(string); ok {
		if s := strings.TrimSpace(cve); s != "" {
			return s
		}
	}
	if ids, ok := vm["ids"].([]any); ok {
		for _, e := range ids {
			em, ok := e.(map[string]any)
			if !ok {
				continue
			}
			if text, ok := em["text"].(string); ok {
				if s := strings.TrimSpace(text); s != "" {
					return s
				}
			}
		}
	}
	return ""
}

// hasCVSSv3Score reports whether the vulnerability already carries a cvss_v3
// score body, in which case its severity must not be overridden.
func hasCVSSv3Score(vm map[string]any) bool {
	for _, s := range existingScores(vm) {
		sm, ok := s.(map[string]any)
		if !ok {
			continue
		}
		for _, family := range []string{"cvss_v3", "cvss_v31", "cvss_v30"} {
			if _, ok := sm[family].(map[string]any); ok {
				return true
			}
		}
	}
	return false
}

func existingScores(vm map[string]any) []any {
	if scores, ok := vm["scores"].([]any); ok {
		return scores
	}
	return nil
}

// productIDsOf collects every product_id the vulnerability references in its
// product_status buckets. A CSAF scores[] entry must target product_ids, and
// those referenced in product_status are guaranteed to be defined in the
// product tree (dep-scan enforces that on emit).
func productIDsOf(vm map[string]any) []string {
	ps, ok := vm["product_status"].(map[string]any)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	var ids []string
	for _, bucket := range ps {
		list, ok := bucket.([]any)
		if !ok {
			continue
		}
		for _, raw := range list {
			id, ok := raw.(string)
			if !ok {
				continue
			}
			id = strings.TrimSpace(id)
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids
}

// normalizeCVSSSeverity maps a VDR rating severity to the upper-case CVSS v3
// qualitative label DefectDojo's CVSS3_SEVERITY table recognizes, or "" when it
// is not a severity this backfill should emit.
func normalizeCVSSSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM", "MODERATE":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	case "NONE", "INFO", "INFORMATIONAL":
		return "NONE"
	default:
		return ""
	}
}

func cvssSeverityRank(label string) int {
	switch label {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "NONE":
		return 1
	default:
		return 0
	}
}
