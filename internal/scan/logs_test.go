package scan

import "testing"

func TestExtractReports(t *testing.T) {
	logs := "[depscan-operator] scanning\n" +
		VDRBegin + "\n{\"vulnerabilities\":[]}\n" + VDREnd + "\n" +
		CSAFBegin + "\n{\"document\":{}}\n" + CSAFEnd + "\n"

	vdr, csaf := ExtractReports(logs, "")
	if vdr != `{"vulnerabilities":[]}` {
		t.Errorf("vdr = %q", vdr)
	}
	if csaf != `{"document":{}}` {
		t.Errorf("csaf = %q", csaf)
	}
}

func TestExtractReportsMissing(t *testing.T) {
	vdr, csaf := ExtractReports("no markers here", "")
	if vdr != "" || csaf != "" {
		t.Errorf("expected empty, got vdr=%q csaf=%q", vdr, csaf)
	}
}

func TestExtractReportsNonceRejectsForgedBlock(t *testing.T) {
	// Image-derived output printed before the real block, using the guessable
	// legacy markers, must not be picked up.
	vb, ve, cb, ce := Markers("s3cr3t")
	logs := VDRBegin + `{"forged":true}` + VDREnd + "\n" +
		vb + `{"real":true}` + ve + "\n" + cb + `{"csaf":1}` + ce
	vdr, csaf := ExtractReports(logs, "s3cr3t")
	if vdr != `{"real":true}` || csaf != `{"csaf":1}` {
		t.Errorf("got vdr=%q csaf=%q", vdr, csaf)
	}
}
