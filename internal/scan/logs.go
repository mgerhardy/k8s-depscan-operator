package scan

import "strings"

// ExtractReports pulls the VDR and CSAF JSON payloads out of the scan pod's
// stdout, which brackets each report with the marker constants.
func ExtractReports(logs string) (vdr string, csaf string) {
	return between(logs, VDRBegin, VDREnd), between(logs, CSAFBegin, CSAFEnd)
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
