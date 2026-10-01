package v1alpha1

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// crdSchema returns the openAPIV3Schema of a generated CRD in config/crd.
func crdSchema(t *testing.T, file string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../config/crd/" + file)
	if err != nil {
		t.Fatal(err)
	}
	var crd map[string]any
	if err := yaml.Unmarshal(raw, &crd); err != nil {
		t.Fatal(err)
	}
	return crd["spec"].(map[string]any)["versions"].([]any)[0].(map[string]any)["schema"].(map[string]any)["openAPIV3Schema"].(map[string]any)
}

// schemaAt walks the generated DepScanConfig CRD schema to a spec property.
func schemaAt(t *testing.T, path ...string) map[string]any {
	t.Helper()
	node := crdSchema(t, "depscan.io_depscanconfigs.yaml")
	node = node["properties"].(map[string]any)["spec"].(map[string]any)
	for _, p := range path {
		node = node["properties"].(map[string]any)[p].(map[string]any)
	}
	return node
}

var celMatches = regexp.MustCompile(`matches\('([^']+)'\)`)

// fieldRegex returns the regex enforcing a field: its pattern, or the regex in
// its CEL matches() rule.
func fieldRegex(t *testing.T, path ...string) *regexp.Regexp {
	t.Helper()
	node := schemaAt(t, path...)
	if p, ok := node["pattern"].(string); ok {
		return regexp.MustCompile(p)
	}
	if ap, ok := node["additionalProperties"].(map[string]any); ok {
		if p, ok := ap["pattern"].(string); ok {
			return regexp.MustCompile(p) // map of quantities
		}
	}
	for _, r := range node["x-kubernetes-validations"].([]any) {
		if m := celMatches.FindStringSubmatch(r.(map[string]any)["rule"].(string)); m != nil {
			return regexp.MustCompile(m[1])
		}
	}
	t.Fatalf("no validation regex on %s", strings.Join(path, "."))
	return nil
}

func TestQuantityValidation(t *testing.T) {
	for _, path := range [][]string{{"scanWorkSizeLimit"}, {"vdbCache", "size"}, {"resources", "requests"}} {
		re := fieldRegex(t, path...)
		for _, ok := range []string{"100Gi", "5Gi", "500m", "2", "1.5G", "512Mi"} {
			if !re.MatchString(ok) {
				t.Errorf("%v: %q should be accepted", path, ok)
			}
		}
		bad := []string{"10GB", "lots", "", "1 Gi"}
		if path[0] != "resources" { // the built-in quantity schema allows a sign
			bad = append(bad, "-1Gi")
		}
		for _, v := range bad {
			if re.MatchString(v) {
				t.Errorf("%v: %q should be rejected", path, v)
			}
		}
	}
}

func TestDurationValidation(t *testing.T) {
	for _, path := range [][]string{{"rescanInterval"}, {"scanTimeout"}, {"vdbCache", "refreshInterval"}, {"vdbCache", "primeTimeout"}} {
		re := fieldRegex(t, path...)
		for _, ok := range []string{"24h", "90m", "1h30m", "30s", "0.5h"} {
			if !re.MatchString(ok) {
				t.Errorf("%v: %q should be accepted", path, ok)
			}
		}
		for _, bad := range []string{"1 day", "24", "1d", ""} {
			if re.MatchString(bad) {
				t.Errorf("%v: %q should be rejected", path, bad)
			}
		}
	}
}

func TestConfigMustBeNamedDefault(t *testing.T) {
	root := crdSchema(t, "depscan.io_depscanconfigs.yaml")
	rules, _ := root["x-kubernetes-validations"].([]any)
	if len(rules) != 1 || rules[0].(map[string]any)["rule"] != "self.metadata.name == 'default'" {
		t.Errorf("root validation = %v", rules)
	}
}

// The API server rejects CRDs whose CEL rules exceed the cost budget; keep
// rules on maps bounded by maxProperties.
func TestResourceMapsAreBounded(t *testing.T) {
	for _, f := range []string{"requests", "limits"} {
		node := schemaAt(t, "resources", f)
		if node["maxProperties"] == nil {
			t.Errorf("resources.%s needs maxProperties to bound its CEL rule cost", f)
		}
	}
}

// Summary counts must never be required: an object lacking one would then
// have every status merge patch rejected (seen on k3s).
func TestReportSummaryHasNoRequiredFields(t *testing.T) {
	summary := crdSchema(t, "depscan.io_depscanreports.yaml")["properties"].(map[string]any)["status"].(map[string]any)["properties"].(map[string]any)["summary"].(map[string]any)
	if req, ok := summary["required"]; ok {
		t.Errorf("status.summary must not have required fields, got %v", req)
	}
}
