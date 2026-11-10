package defectdojo

import (
	"encoding/json"
	"strings"
)

// maxCVELen is DefectDojo's Finding.cve column width (varchar(50)). A CSAF
// vulnerability whose "cve" exceeds it makes the whole reimport fail with
// HTTP 500 (StringDataRightTruncation), so the value is capped before upload.
const maxCVELen = 50

// SanitizeCSAFForDefectDojo caps each vulnerabilities[].cve in a dep-scan CSAF
// document to what DefectDojo's Finding.cve column accepts (varchar(50)).
//
// dep-scan sometimes emits a composite identifier in the CSAF "cve" field --
// the advisory id joined to the affected package URL, e.g.
// "GO-2026-5932/pkg:golang/golang.org/x/crypto@v0.55.0" (51 chars). DefectDojo
// stores that field verbatim in a 50-char column, so a single such finding
// makes the entire reimport-scan POST return HTTP 500 and the report is lost.
//
// The fix keeps the advisory id (the part before the first "/"), which is the
// real vulnerability identifier and almost always well under the limit; the
// package-URL suffix is noise in a CVE field (the component is carried
// elsewhere in the CSAF product tree). If the advisory id alone is still too
// long it is hard-truncated so the upload can never overflow the column.
//
// Input that is not valid JSON, or has no over-long cve, is returned unchanged
// so a parsing quirk can never drop a report that would otherwise import.
func SanitizeCSAFForDefectDojo(csaf []byte) []byte {
	if len(csaf) == 0 {
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
		cve, ok := vm["cve"].(string)
		if !ok || len(cve) <= maxCVELen {
			continue
		}
		vm["cve"] = capCVE(cve)
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

// capCVE reduces an over-long CSAF cve value to fit DefectDojo's column: prefer
// the advisory id before the first "/", then hard-truncate as a last resort.
func capCVE(cve string) string {
	if id, _, found := strings.Cut(cve, "/"); found && len(id) <= maxCVELen && id != "" {
		return id
	}
	return cve[:maxCVELen]
}
