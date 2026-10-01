package scan

import "strings"

// Markers returns the four report markers for a scan Job. The nonce is a
// per-Job secret embedded in the markers so output derived from the scanned
// image cannot forge a report block.
func Markers(nonce string) (vdrBegin, vdrEnd, csafBegin, csafEnd string) {
	sfx := func(m string) string { return strings.TrimSuffix(m, "---") + "-" + nonce + "---" }
	return sfx(VDRBegin), sfx(VDREnd), sfx(CSAFBegin), sfx(CSAFEnd)
}

// ExtractReports pulls the VDR and CSAF JSON payloads out of the scan pod's
// stdout, which brackets each report with the markers for nonce. Without a
// nonce nothing is extracted: the bare markers are guessable.
func ExtractReports(logs, nonce string) (vdr string, csaf string) {
	if nonce == "" {
		return "", ""
	}
	vb, ve, cb, ce := Markers(nonce)
	return between(logs, vb, ve), between(logs, cb, ce)
}

func between(s, begin, end string) string {
	bi := strings.Index(s, begin)
	if bi < 0 {
		return ""
	}
	rest := s[bi+len(begin):]
	ei := strings.Index(rest, end)
	if ei < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:ei])
}
