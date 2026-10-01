// Package dockercfg builds the registry credentials a scan uses to pull an
// image. It resolves wildcard registry entries (e.g. "*.example.com") to the
// image's concrete host, because kubelet matches such wildcards but the
// in-pod puller matches only an exact host.
package dockercfg

import (
	"encoding/json"
	"strings"
)

// dockerHubKey is the auths key docker-config readers look up for Docker Hub.
const dockerHubKey = "https://index.docker.io/v1/"

type dockerConfig struct {
	Auths map[string]json.RawMessage `json:"auths"`
}

// Build merges the given dockerconfigjson secret payloads and returns a
// config.json holding only the credentials that apply to the image's
// registry, keyed so the in-pod puller finds them (the concrete host for
// wildcard entries, the canonical key for Docker Hub). Credentials for other
// registries are dropped so they are never copied out of the workload's
// namespace. Returns (nil, false) when no credential applies, so the caller
// can skip mounting credentials and pull anonymously.
func Build(image string, secretPayloads [][]byte) ([]byte, bool) {
	host := registryHost(image)

	merged := map[string]json.RawMessage{}
	for _, raw := range secretPayloads {
		var cfg dockerConfig
		if err := json.Unmarshal(raw, &cfg); err != nil {
			continue
		}
		for reg, auth := range cfg.Auths {
			norm := normalizeKey(reg)
			switch {
			case isDockerHub(host):
				if isDockerHub(norm) {
					merged[dockerHubKey] = auth
				}
			case norm == host:
				merged[reg] = auth
				merged[host] = auth
			case matchesWildcard(norm, host):
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

// registryHost returns the lower-cased registry host[:port] of an image
// reference, or "" for a bare Docker Hub image.
func registryHost(image string) string {
	first := image
	if i := strings.Index(first, "/"); i >= 0 {
		first = first[:i]
	} else {
		return ""
	}
	if strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost" {
		return strings.ToLower(first)
	}
	return ""
}

// normalizeKey reduces an auths key such as "https://reg.example.com/v1/" to
// its lower-cased host[:port], the form kubelet matches on.
func normalizeKey(key string) string {
	k := strings.ToLower(strings.TrimSpace(key))
	if i := strings.Index(k, "://"); i >= 0 {
		k = k[i+3:]
	}
	if i := strings.Index(k, "/"); i >= 0 {
		k = k[:i]
	}
	return k
}

func isDockerHub(host string) bool {
	switch host {
	case "", "docker.io", "index.docker.io", "registry-1.docker.io":
		return true
	}
	return false
}

// matchesWildcard reports whether a "*."-prefixed registry pattern covers host.
func matchesWildcard(pattern, host string) bool {
	if !strings.HasPrefix(pattern, "*.") || host == "" {
		return false
	}
	return strings.HasSuffix(host, pattern[1:]) // drop the '*'
}
