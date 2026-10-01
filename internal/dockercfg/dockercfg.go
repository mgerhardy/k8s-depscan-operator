// Package dockercfg builds the registry credentials a scan uses to pull an
// image. It resolves wildcard registry entries (e.g. "*.example.com") to the
// image's concrete host, because kubelet matches such wildcards but the
// in-pod puller matches only an exact host.
package dockercfg

import (
	"encoding/json"
	"strings"
)

type dockerConfig struct {
	Auths map[string]json.RawMessage `json:"auths"`
}

// Build merges the given dockerconfigjson secret payloads and returns a
// config.json whose auths include an exact entry for the image's registry
// host. Returns (nil, false) when no credential applies, so the caller can
// skip mounting credentials and pull anonymously.
func Build(image string, secretPayloads [][]byte) ([]byte, bool) {
	host := registryHost(image)

	merged := map[string]json.RawMessage{}
	for _, raw := range secretPayloads {
		var cfg dockerConfig
		if err := json.Unmarshal(raw, &cfg); err != nil {
			continue
		}
		for reg, auth := range cfg.Auths {
			merged[reg] = auth
			if host != "" && matchesWildcard(reg, host) {
				merged[host] = auth
			}
		}
	}
	if len(merged) == 0 {
		return nil, false
	}
	out, err := json.Marshal(dockerConfig{Auths: merged})
	if err != nil {
		return nil, false
	}
	return out, true
}

// registryHost returns the registry host of an image reference, or "" for a
// bare Docker Hub image (which needs no wildcard resolution).
func registryHost(image string) string {
	first := image
	if i := strings.Index(first, "/"); i >= 0 {
		first = first[:i]
	} else {
		return ""
	}
	if strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost" {
		return first
	}
	return ""
}

// matchesWildcard reports whether a "*."-prefixed registry pattern covers host.
func matchesWildcard(pattern, host string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	return strings.HasSuffix(host, pattern[1:]) // drop the '*'
}
