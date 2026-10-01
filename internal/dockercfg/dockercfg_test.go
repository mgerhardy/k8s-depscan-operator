package dockercfg

import (
	"encoding/json"
	"testing"
)

func authsOf(t *testing.T, cfg []byte) map[string]json.RawMessage {
	t.Helper()
	var d dockerConfig
	if err := json.Unmarshal(cfg, &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return d.Auths
}

func TestBuildExpandsWildcardToImageHost(t *testing.T) {
	secret := []byte(`{"auths":{"*.example.com":{"auth":"dXNlcjpwYXNz"}}}`)
	cfg, ok := Build("reg.example.com/ns/app:1.0", [][]byte{secret})
	if !ok {
		t.Fatal("expected credentials")
	}
	auths := authsOf(t, cfg)
	if _, ok := auths["reg.example.com"]; !ok {
		t.Errorf("wildcard not expanded to concrete host; got %v", keys(auths))
	}
	if _, ok := auths["*.example.com"]; !ok {
		t.Errorf("original wildcard entry should be kept")
	}
}

func TestBuildExactHostKept(t *testing.T) {
	secret := []byte(`{"auths":{"reg.example.com":{"auth":"eA=="}}}`)
	cfg, ok := Build("reg.example.com/app:1", [][]byte{secret})
	if !ok {
		t.Fatal("expected credentials")
	}
	if _, ok := authsOf(t, cfg)["reg.example.com"]; !ok {
		t.Error("exact host entry missing")
	}
}

func TestBuildNoMatchingCreds(t *testing.T) {
	secret := []byte(`{"auths":{"other.example.net":{"auth":"eA=="}}}`)
	// Entry does not match the image host, but Build still returns the config
	// (crane simply won't find an entry for the host and pulls anonymously).
	cfg, ok := Build("reg.example.com/app:1", [][]byte{secret})
	if !ok {
		t.Fatal("expected a config with the unrelated entry")
	}
	if _, ok := authsOf(t, cfg)["reg.example.com"]; ok {
		t.Error("should not fabricate an entry for an unmatched host")
	}
}

func TestBuildEmpty(t *testing.T) {
	if _, ok := Build("reg.example.com/app:1", nil); ok {
		t.Error("expected ok=false with no secrets")
	}
}

func TestRegistryHost(t *testing.T) {
	cases := map[string]string{
		"reg.example.com/ns/app:1":      "reg.example.com",
		"localhost:5000/app":            "localhost:5000",
		"nginx:1.25":                    "",
		"library/nginx:1.25":            "",
		"ghcr.io/owner/app@sha256:abcd": "ghcr.io",
	}
	for img, want := range cases {
		if got := registryHost(img); got != want {
			t.Errorf("registryHost(%q) = %q, want %q", img, got, want)
		}
	}
}

func TestMatchesWildcard(t *testing.T) {
	if !matchesWildcard("*.example.com", "a.b.example.com") {
		t.Error("should match nested subdomain")
	}
	if matchesWildcard("reg.example.com", "reg.example.com") {
		t.Error("non-wildcard pattern must not match as wildcard")
	}
	if matchesWildcard("*.example.com", "example.org") {
		t.Error("different domain must not match")
	}
}

func keys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
