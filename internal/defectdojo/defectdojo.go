// Package defectdojo uploads dep-scan CSAF VEX reports to a DefectDojo
// instance via the /api/v2/reimport-scan/ endpoint: a multipart upload with
// auto_create_context, authenticated by an API token or HTTP Basic auth, so
// products/engagements/tests are created on demand and re-uploads update
// existing findings rather than duplicating them.
package defectdojo

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

// Uploader sends reports to a DefectDojo instance. Authentication uses an API
// token when Token is set, otherwise HTTP Basic auth with Username/Password.
type Uploader struct {
	BaseURL    string
	Username   string
	Password   string
	Token      string
	HTTPClient *http.Client
	// AllowInsecure permits a plain http:// URL. Off by default so credentials
	// and reports are not sent in cleartext by misconfiguration.
	AllowInsecure bool
}

// New builds an Uploader with sane defaults.
func New(baseURL, username, password string) *Uploader {
	if username == "" {
		username = "admin"
	}
	return &Uploader{
		BaseURL:  strings.TrimRight(baseURL, "/"),
		Username: username,
		Password: password,
		HTTPClient: &http.Client{
			Timeout: 5 * time.Minute,
			// A followed redirect turns the POST into a body-less GET whose
			// 200 would look like a successful import; surface it instead.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// ReimportParams carries the per-upload metadata.
type ReimportParams struct {
	ScanType         string
	ProductName      string
	ProductType      string
	EngagementName   string
	TestTitle        string
	Filename         string
	Report           []byte
	CloseOldFindings bool
}

// Reimport performs a multipart POST to /api/v2/reimport-scan/.
func (u *Uploader) Reimport(ctx context.Context, p ReimportParams) error {
	if u.Token == "" && u.Password == "" {
		return fmt.Errorf("defectdojo: no credentials set (need a token or password)")
	}
	if !u.AllowInsecure && !strings.HasPrefix(u.BaseURL, "https://") {
		return fmt.Errorf("defectdojo: refusing to send credentials over non-https URL %q (set allowInsecure to override)", u.BaseURL)
	}
	if p.ScanType == "" {
		p.ScanType = "CSAF Scan"
	}
	if p.ProductType == "" {
		p.ProductType = "Research and Development"
	}

	var body bytes.Buffer
	w := multipart.NewWriter(&body)

	fields := map[string]string{
		"scan_type":                   p.ScanType,
		"product_name":                p.ProductName,
		"product_type_name":           p.ProductType,
		"engagement_name":             p.EngagementName,
		"test_title":                  p.TestTitle,
		"auto_create_context":         "true",
		"active":                      "true",
		"verified":                    "false",
		"close_old_findings":          boolStr(p.CloseOldFindings),
		"deduplication_on_engagement": "true",
	}
	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			return fmt.Errorf("defectdojo: write field %s: %w", k, err)
		}
	}

	filename := p.Filename
	if filename == "" {
		filename = "report.json"
	}
	part, err := w.CreateFormFile("file", filename)
	if err != nil {
		return fmt.Errorf("defectdojo: create file part: %w", err)
	}
	if _, err := part.Write(p.Report); err != nil {
		return fmt.Errorf("defectdojo: write report: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("defectdojo: close multipart writer: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		u.BaseURL+"/api/v2/reimport-scan/", &body)
	if err != nil {
		return fmt.Errorf("defectdojo: build request: %w", err)
	}
	if u.Token != "" {
		req.Header.Set("Authorization", "Token "+u.Token)
	} else {
		auth := base64.StdEncoding.EncodeToString([]byte(u.Username + ":" + u.Password))
		req.Header.Set("Authorization", "Basic "+auth)
	}
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := u.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("defectdojo: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 500))
		return &HTTPError{StatusCode: resp.StatusCode, Body: string(snippet)}
	}
	return nil
}

// HTTPError is a non-2xx DefectDojo response. Body holds the start of the
// response, which may contain server detail; keep it out of user-visible
// status.
type HTTPError struct {
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("defectdojo: HTTP %d: %s", e.StatusCode, e.Body)
}

// Describe returns a short, safe-to-display qualifier for an export error
// (e.g. " (HTTP 403)"), without response bodies or credentials.
func Describe(err error) string {
	var he *HTTPError
	if errors.As(err, &he) {
		return fmt.Sprintf(" (HTTP %d)", he.StatusCode)
	}
	return ""
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
