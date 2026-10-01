// Package naming derives stable, DNS-safe Kubernetes object names from image
// references so each (namespace, image) pair maps to exactly one report.
package naming

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// ImageKey returns a short, stable hex key for an image reference. It is used
// both as a label value and as part of object names.
func ImageKey(image string) string {
	sum := sha256.Sum256([]byte(image))
	return hex.EncodeToString(sum[:])[:16]
}

// ReportName builds a DNS-1123 subdomain name for a DepScanReport from the
// image reference. The human-readable prefix aids debugging; the hash suffix
// guarantees uniqueness and avoids collisions after sanitization.
func ReportName(image string) string {
	return sanitizedName("depscanreport", image)
}

// JobName builds a DNS-1123 label-safe name for the scan Job of an image in
// a namespace. The namespace is part of the hash so reports in different
// namespaces never share (or delete) each other's Job, which also keeps one
// namespace's registry credentials from serving another's scan.
func JobName(namespace, image string) string {
	readable := truncate(strings.Trim(nonAlnum.ReplaceAllString(strings.ToLower(image), "-"), "-"), 30)
	// Job names feed pod/label values (max 63 chars), so keep it compact.
	return truncate(fmt.Sprintf("depscan-%s-%s", readable, ImageKey(namespace+"/"+image)), 63)
}

func sanitizedName(prefix, image string) string {
	readable := nonAlnum.ReplaceAllString(strings.ToLower(image), "-")
	readable = strings.Trim(readable, "-")
	// Keep the readable portion bounded so prefix+readable+hash fits limits.
	readable = truncate(readable, 30)
	return fmt.Sprintf("%s-%s-%s", prefix, readable, ImageKey(image))
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return strings.Trim(s[:max], "-")
}
