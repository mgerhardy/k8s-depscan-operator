// Package scan parses OWASP dep-scan output (a CycloneDX VDR JSON document)
// into the operator's CRD types.
package scan

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
)

// vdr is a minimal projection of the CycloneDX VDR document emitted by dep-scan.
type vdr struct {
	Vulnerabilities []vdrVuln `json:"vulnerabilities"`
}

type vdrVuln struct {
	ID       string        `json:"id"`
	BOMRef   string        `json:"bom-ref"`
	Ratings  []vdrRating   `json:"ratings"`
	Affects  []vdrAffect   `json:"affects"`
	Analysis *vdrAnalysis  `json:"analysis"`
	Props    []vdrProperty `json:"properties"`
	// recommendation sometimes carries the fixed version in dep-scan output.
	Recommendation string      `json:"recommendation"`
	Source         *vdrSource  `json:"source"`
	Description    string      `json:"description"`
	Advisories     []vdrAdvRef `json:"advisories"`
}

type vdrRating struct {
	Severity string   `json:"severity"`
	Score    *float64 `json:"score"`
	Method   string   `json:"method"`
}

type vdrAffect struct {
	Ref string `json:"ref"`
}

type vdrAnalysis struct {
	State  string `json:"state"`
	Detail string `json:"detail"`
}

type vdrProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type vdrSource struct {
	URL  string `json:"url"`
	Name string `json:"name"`
}

type vdrAdvRef struct {
	URL string `json:"url"`
}

// Result holds the parsed, normalized findings plus a severity summary.
type Result struct {
	Vulnerabilities []depscanv1alpha1.Vulnerability
	Summary         depscanv1alpha1.VulnerabilitySummary
	// ReachabilityAnalyzed reports whether dep-scan ran reachability analysis
	// for this scan (derived from the CSAF VEX report).
	ReachabilityAnalyzed bool
}

// IsCycloneDX reports whether data is a CycloneDX JSON document. The operator
// uses it to refuse ingesting a missing or placeholder report as "no findings".
func IsCycloneDX(data []byte) bool {
	var head struct {
		BOMFormat string `json:"bomFormat"`
	}
	return json.Unmarshal(data, &head) == nil && head.BOMFormat == "CycloneDX"
}

// ParseVDR parses a dep-scan CycloneDX VDR JSON document without CSAF VEX
// reachability. Reachability verdicts come only from VDR insights, so most
// findings are reported as unknown. Prefer ParseReports when the CSAF document
// is available.
func ParseVDR(data []byte) (*Result, error) {
	return ParseReports(data, nil)
}

// ParseReports parses a dep-scan CycloneDX VDR document and, when provided, the
// matching CSAF VEX document. CSAF carries dep-scan's authoritative three-way
// reachability (reachable / not-reachable / not-analyzed), so when present it
// decides each finding's reachability by CVE id, overriding the VDR insight.
func ParseReports(vdrData, csafData []byte) (*Result, error) {
	var doc vdr
	if err := json.Unmarshal(vdrData, &doc); err != nil {
		return nil, fmt.Errorf("decode dep-scan VDR: %w", err)
	}

	csaf := parseCSAFReachability(csafData)

	res := &Result{ReachabilityAnalyzed: csaf.analyzed}
	for _, v := range doc.Vulnerabilities {
		reach := reachabilityFrom(v)
		// CSAF VEX is authoritative for reachability: it distinguishes
		// not-reachable (analyzed, code not on an execute path) from unknown
		// (not analyzed), which VDR insights cannot express.
		if verdict, ok := csaf.byCVE[v.ID]; ok {
			reach = verdict
		}
		vuln := depscanv1alpha1.Vulnerability{
			VulnerabilityID: truncate(v.ID, maxIDLen),
			Severity:        normalizeSeverity(topRating(v.Ratings).Severity),
			Title:           firstNonEmpty(truncate(v.Description, maxTitleLen)),
			Reachability:    reach,
		}
		if r := topRating(v.Ratings); r.Score != nil {
			vuln.Score = strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.1f", *r.Score), "0"), ".")
		}
		if v.Source != nil && v.Source.URL != "" {
			vuln.PrimaryLink = v.Source.URL
		} else if len(v.Advisories) > 0 {
			vuln.PrimaryLink = v.Advisories[0].URL
		}
		vuln.PrimaryLink = truncate(vuln.PrimaryLink, maxLinkLen)
		purl := affectedPURL(v)
		vuln.PURL = truncate(purl, maxPURLLen)
		name, version := packageFromPURL(purl)
		vuln.Resource, vuln.InstalledVersion = truncate(name, maxNameLen), truncate(version, maxVersionLen)
		vuln.FixedVersion = truncate(fixedVersionFromProps(v), maxVersionLen)

		res.Vulnerabilities = append(res.Vulnerabilities, vuln)
		countSeverity(&res.Summary, vuln.Severity)
		res.Summary.TotalCount++
		switch vuln.Reachability {
		case depscanv1alpha1.ReachabilityReachable:
			res.Summary.ReachableCount++
			switch vuln.Severity {
			case depscanv1alpha1.SeverityCritical:
				res.Summary.ReachableCriticalCount++
			case depscanv1alpha1.SeverityHigh:
				res.Summary.ReachableHighCount++
			}
		case depscanv1alpha1.ReachabilityNotReachable:
			res.Summary.NotReachableCount++
		default:
			res.Summary.UnknownReachabilityCount++
		}
	}

	sort.Slice(res.Vulnerabilities, func(i, j int) bool {
		si, sj := severityRank(res.Vulnerabilities[i].Severity), severityRank(res.Vulnerabilities[j].Severity)
		if si != sj {
			return si > sj
		}
		return res.Vulnerabilities[i].VulnerabilityID < res.Vulnerabilities[j].VulnerabilityID
	})
	return res, nil
}

func topRating(ratings []vdrRating) vdrRating {
	best := vdrRating{}
	bestRank := -1
	for _, r := range ratings {
		if rank := severityRank(normalizeSeverity(r.Severity)); rank > bestRank {
			bestRank = rank
			best = r
		}
	}
	return best
}

func reachabilityFrom(v vdrVuln) depscanv1alpha1.Reachability {
	// dep-scan marks reachable findings via the "depscan:insights" property,
	// whose multi-line value carries a "Reachable" token for application
	// dependencies its code analysis can trace. A dedicated reachability
	// property is also honored if a future dep-scan version emits one.
	for _, p := range v.Props {
		name := strings.ToLower(p.Name)
		// Normalize separators so "not-reachable", "not_reachable" and
		// "not reachable" are all detected.
		val := strings.NewReplacer("-", " ", "_", " ").Replace(strings.ToLower(p.Value))
		if name == "depscan:insights" || strings.Contains(name, "reachab") {
			switch {
			case strings.Contains(val, "unreachable") || strings.Contains(val, "not reachable"):
				return depscanv1alpha1.ReachabilityNotReachable
			case strings.Contains(val, "reachable"):
				return depscanv1alpha1.ReachabilityReachable
			}
		}
	}
	// analysis.state is a VEX adjudication state, not a reachability verdict:
	// dep-scan defaults it to "in_triage". Only clearly-negative states imply
	// the code path is not a concern; anything else stays unknown.
	if v.Analysis != nil {
		switch strings.ToLower(v.Analysis.State) {
		case "not_affected", "false_positive", "resolved", "resolved_with_pedigree":
			return depscanv1alpha1.ReachabilityNotReachable
		}
	}
	return depscanv1alpha1.ReachabilityUnknown
}

func affectedPURL(v vdrVuln) string {
	if len(v.Affects) > 0 {
		return v.Affects[0].Ref
	}
	return v.BOMRef
}

// packageFromPURL extracts a human package name and version from a purl like
// pkg:deb/debian/openssl@1.1.1n-0+deb11u5?arch=amd64
func packageFromPURL(purl string) (name, version string) {
	if purl == "" {
		return "", ""
	}
	p := purl
	if idx := strings.Index(p, "?"); idx >= 0 {
		p = p[:idx]
	}
	at := strings.LastIndex(p, "@")
	if at >= 0 {
		version = p[at+1:]
		p = p[:at]
	}
	segs := strings.Split(strings.TrimPrefix(p, "pkg:"), "/")
	if len(segs) > 0 {
		name = segs[len(segs)-1]
	}
	return name, version
}

func fixedVersionFromProps(v vdrVuln) string {
	for _, p := range v.Props {
		n := strings.ToLower(p.Name)
		if strings.Contains(n, "fixed") || strings.Contains(n, "fix_version") {
			return p.Value
		}
	}
	return ""
}

func normalizeSeverity(s string) depscanv1alpha1.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return depscanv1alpha1.SeverityCritical
	case "HIGH":
		return depscanv1alpha1.SeverityHigh
	case "MEDIUM", "MODERATE":
		return depscanv1alpha1.SeverityMedium
	case "LOW":
		return depscanv1alpha1.SeverityLow
	case "NONE", "INFO", "INFORMATIONAL":
		return depscanv1alpha1.SeverityNone
	default:
		return depscanv1alpha1.SeverityUnknown
	}
}

func severityRank(s depscanv1alpha1.Severity) int {
	switch s {
	case depscanv1alpha1.SeverityCritical:
		return 5
	case depscanv1alpha1.SeverityHigh:
		return 4
	case depscanv1alpha1.SeverityMedium:
		return 3
	case depscanv1alpha1.SeverityLow:
		return 2
	case depscanv1alpha1.SeverityNone:
		return 1
	default:
		return 0
	}
}

func countSeverity(sum *depscanv1alpha1.VulnerabilitySummary, s depscanv1alpha1.Severity) {
	switch s {
	case depscanv1alpha1.SeverityCritical:
		sum.CriticalCount++
	case depscanv1alpha1.SeverityHigh:
		sum.HighCount++
	case depscanv1alpha1.SeverityMedium:
		sum.MediumCount++
	case depscanv1alpha1.SeverityLow:
		sum.LowCount++
	case depscanv1alpha1.SeverityNone:
		sum.NoneCount++
	default:
		sum.UnknownCount++
	}
}

// Field length caps (bytes). Package names, versions and purls come from the
// scanned image, so they are attacker-influenced and must be bounded to keep
// the report object within etcd's size limit.
const (
	maxIDLen      = 128
	maxTitleLen   = 200
	maxNameLen    = 256
	maxVersionLen = 128
	maxPURLLen    = 512
	maxLinkLen    = 512
)

// truncate trims s and cuts it to at most max bytes without splitting a UTF-8
// sequence.
func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
