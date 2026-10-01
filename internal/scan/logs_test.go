package scan

import "testing"

func TestExtractReports(t *testing.T) {
	logs := "[depscan-operator] scanning\n" +
		VDRBegin + "\n{\"vulnerabilities\":[]}\n" + VDREnd + "\n" +
		CSAFBegin + "\n{\"document\":{}}\n" + CSAFEnd + "\n"

	vdr, csaf := ExtractReports(logs)
	if vdr != `{"vulnerabilities":[]}` {
		t.Errorf("vdr = %q", vdr)
	}
	if csaf != `{"document":{}}` {
		t.Errorf("csaf = %q", csaf)
	}
}

func TestExtractReportsMissing(t *testing.T) {
	vdr, csaf := ExtractReports("no markers here")
	if vdr != "" || csaf != "" {
		t.Errorf("expected empty, got vdr=%q csaf=%q", vdr, csaf)
	}
}
