package scan

import "testing"

func TestExtractReports(t *testing.T) {
	vb, ve, cb, ce := Markers("n0nce")
	logs := "[depscan-operator] scanning\n" +
		vb + "\n{\"vulnerabilities\":[]}\n" + ve + "\n" +
		cb + "\n{\"document\":{}}\n" + ce + "\n"

	vdr, csaf := ExtractReports(logs, "n0nce")
	if vdr != `{"vulnerabilities":[]}` {
		t.Errorf("vdr = %q", vdr)
	}
	if csaf != `{"document":{}}` {
		t.Errorf("csaf = %q", csaf)
	}
}

func TestExtractReportsMissing(t *testing.T) {
	vdr, csaf := ExtractReports("no markers here", "n0nce")
	if vdr != "" || csaf != "" {
		t.Errorf("expected empty, got vdr=%q csaf=%q", vdr, csaf)
	}
}

func TestExtractReportsRequiresNonce(t *testing.T) {
	logs := VDRBegin + `{"forged":true}` + VDREnd
	if vdr, _ := ExtractReports(logs, ""); vdr != "" {
		t.Errorf("bare markers must not be extracted, got %q", vdr)
	}
}

func TestExtractReportsNonceRejectsForgedBlock(t *testing.T) {
	// Image-derived output printed before the real block, using the guessable
	// bare markers, must not be picked up.
	vb, ve, cb, ce := Markers("s3cr3t")
	logs := VDRBegin + `{"forged":true}` + VDREnd + "\n" +
		vb + `{"real":true}` + ve + "\n" + cb + `{"csaf":1}` + ce
	vdr, csaf := ExtractReports(logs, "s3cr3t")
	if vdr != `{"real":true}` || csaf != `{"csaf":1}` {
		t.Errorf("got vdr=%q csaf=%q", vdr, csaf)
	}
}
