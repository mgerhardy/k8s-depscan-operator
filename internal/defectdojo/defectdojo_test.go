package defectdojo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReimport(t *testing.T) {
	var gotPath, gotAuth, gotScanType, gotProduct, gotAutoCreate, gotFilename string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Fatalf("parse multipart: %v", err)
		}
		gotScanType = r.FormValue("scan_type")
		gotProduct = r.FormValue("product_name")
		gotAutoCreate = r.FormValue("auto_create_context")
		if f, hdr, err := r.FormFile("file"); err == nil {
			gotFilename = hdr.Filename
			_ = f.Close()
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"test": 1}`))
	}))
	defer srv.Close()

	u := New(srv.URL, "", "s3cret") // empty user defaults to admin
	u.AllowInsecure = true          // httptest server is plain http
	err := u.Reimport(context.Background(), ReimportParams{
		ScanType:         "CSAF Scan",
		ProductName:      "demo-namespace",
		EngagementName:   "Cluster Dep-Scan",
		TestTitle:        "nginx:latest",
		Filename:         "nginx.csaf.json",
		Report:           []byte(`{"document":{}}`),
		CloseOldFindings: true,
	})
	if err != nil {
		t.Fatalf("Reimport error: %v", err)
	}

	if gotPath != "/api/v2/reimport-scan/" {
		t.Errorf("path = %q", gotPath)
	}
	if !strings.HasPrefix(gotAuth, "Basic ") {
		t.Errorf("auth header = %q, want Basic", gotAuth)
	}
	if gotScanType != "CSAF Scan" {
		t.Errorf("scan_type = %q", gotScanType)
	}
	if gotProduct != "demo-namespace" {
		t.Errorf("product_name = %q", gotProduct)
	}
	if gotAutoCreate != "true" {
		t.Errorf("auto_create_context = %q, want true", gotAutoCreate)
	}
	if gotFilename != "nginx.csaf.json" {
		t.Errorf("filename = %q", gotFilename)
	}
}

func TestReimportTokenAuth(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	u := New(srv.URL, "", "") // no password
	u.AllowInsecure = true
	u.Token = "abc123"
	if err := u.Reimport(context.Background(), ReimportParams{Report: []byte("{}")}); err != nil {
		t.Fatalf("Reimport with token: %v", err)
	}
	if gotAuth != "Token abc123" {
		t.Errorf("auth header = %q, want 'Token abc123'", gotAuth)
	}
}

func TestReimportNoCredentials(t *testing.T) {
	u := New("https://defectdojo.example", "admin", "")
	if err := u.Reimport(context.Background(), ReimportParams{}); err == nil {
		t.Fatal("expected error when neither token nor password is set")
	}
}

func TestReimportRejectsInsecureURL(t *testing.T) {
	u := New("http://defectdojo.example", "admin", "s3cret")
	err := u.Reimport(context.Background(), ReimportParams{Report: []byte("{}")})
	if err == nil {
		t.Fatal("expected http:// URL to be rejected by default")
	}
	// With the opt-in it passes the scheme gate (connection then fails, which is fine).
	u.AllowInsecure = true
	if err := u.Reimport(context.Background(), ReimportParams{Report: []byte("{}")}); err != nil {
		if strings.Contains(err.Error(), "non-https") {
			t.Fatalf("scheme check should be bypassed when AllowInsecure is set: %v", err)
		}
	}
}
