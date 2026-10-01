package scan

import (
	"encoding/json"
	"strings"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
)

// csafDoc is a minimal projection of dep-scan's CSAF VEX document. dep-scan
// records reachability as CSAF product status: a vulnerability's affected
// products land in known_affected (reachable), known_not_affected (analyzed
// but the vulnerable code is not on an execute path), or under_investigation
// (no reachability data). See analysis_lib/vex/reachability.py.
type csafDoc struct {
	Vulnerabilities []csafVuln `json:"vulnerabilities"`
}

type csafVuln struct {
	CVE           string              `json:"cve"`
	ProductStatus map[string][]string `json:"product_status"`
}

// csafReachability is the reachability picture derived from a CSAF VEX report:
// a per-CVE verdict plus whether dep-scan ran reachability analysis at all.
type csafReachability struct {
	byCVE    map[string]depscanv1alpha1.Reachability
	analyzed bool
}

// parseCSAFReachability extracts per-CVE reachability verdicts from a CSAF VEX
// document. It returns analyzed=true when at least one vulnerability carries a
// decided status (known_affected or known_not_affected), mirroring dep-scan's
// own has_reachability test. An empty or unparseable document yields no
// verdicts and analyzed=false.
func parseCSAFReachability(data []byte) csafReachability {
	out := csafReachability{byCVE: map[string]depscanv1alpha1.Reachability{}}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "{}" {
		return out
	}
	var doc csafDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return out
	}
	for _, v := range doc.Vulnerabilities {
		if v.CVE == "" {
			continue
		}
		switch {
		case len(v.ProductStatus["known_affected"]) > 0:
			out.byCVE[v.CVE] = depscanv1alpha1.ReachabilityReachable
			out.analyzed = true
		case len(v.ProductStatus["known_not_affected"]) > 0:
			out.byCVE[v.CVE] = depscanv1alpha1.ReachabilityNotReachable
			out.analyzed = true
		default:
			// under_investigation or no status: no reachability data.
			out.byCVE[v.CVE] = depscanv1alpha1.ReachabilityUnknown
		}
	}
	return out
}
