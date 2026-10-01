package controller

import (
	"testing"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
)

func TestNamespaceInScope(t *testing.T) {
	cfg := depscanv1alpha1.DepScanConfigSpec{
		ExcludeNamespaces: []string{"kube-system"},
	}
	if namespaceInScope("kube-system", cfg) {
		t.Error("kube-system should be excluded")
	}
	if !namespaceInScope("default", cfg) {
		t.Error("default should be in scope with no include list")
	}

	cfg = depscanv1alpha1.DepScanConfigSpec{
		IncludeNamespaces: []string{"prod"},
	}
	if !namespaceInScope("prod", cfg) {
		t.Error("prod should be in scope")
	}
	if namespaceInScope("default", cfg) {
		t.Error("default should be out of scope when include list is set")
	}
}

func TestResolvedImage(t *testing.T) {
	cases := []struct {
		imageID, want string
	}{
		{"docker-pullable://nginx@sha256:abc", "nginx@sha256:abc"},
		{"nginx@sha256:def", "nginx@sha256:def"},
		{"", ""},
		{"containerd://no-digest", ""},
	}
	for _, c := range cases {
		if got := resolvedImage(c.imageID); got != c.want {
			t.Errorf("resolvedImage(%q) = %q, want %q", c.imageID, got, c.want)
		}
	}
}

func TestHasTagOrDigest(t *testing.T) {
	cases := map[string]bool{
		"nginx:1.25":                      true,
		"repo.example.com:5000/app:1.0":   true,
		"repo.example.com/app@sha256:abc": true,
		"nginx":                           false,
		"repo.example.com:5000/app":       false, // registry port, no tag
	}
	for img, want := range cases {
		if got := hasTagOrDigest(img); got != want {
			t.Errorf("hasTagOrDigest(%q) = %v, want %v", img, got, want)
		}
	}
}

func TestRenderProductName(t *testing.T) {
	if got := renderProductName("{namespace}", "demo", "nginx:latest"); got != "demo" {
		t.Errorf("got %q, want demo", got)
	}
	if got := renderProductName("{namespace}/{image}", "demo", "nginx:latest"); got != "demo/nginx:latest" {
		t.Errorf("got %q", got)
	}
	if got := renderProductName("", "demo", "x"); got != "demo" {
		t.Errorf("empty template should default to namespace, got %q", got)
	}
}

func TestWithDefaults(t *testing.T) {
	spec := withDefaults(depscanv1alpha1.DepScanConfigSpec{})
	if spec.ScannerImage == "" {
		t.Error("scanner image should default")
	}
	if spec.RescanInterval.Duration == 0 {
		t.Error("rescan interval should default")
	}
	if spec.JobTTLSeconds == 0 {
		t.Error("job TTL should default")
	}
}
