package naming

import (
	"strings"
	"testing"
)

func TestJobNamePerNamespace(t *testing.T) {
	a, b := JobName("team-a", "nginx:1.25"), JobName("team-b", "nginx:1.25")
	if a == b {
		t.Errorf("same image in different namespaces must get distinct Jobs: %q", a)
	}
	if a != JobName("team-a", "nginx:1.25") {
		t.Error("JobName must be stable")
	}
	long := JobName(strings.Repeat("n", 63), "registry.example.com/"+strings.Repeat("x", 200)+":1")
	if len(long) > 63 || strings.HasSuffix(long, "-") {
		t.Errorf("job name not label-safe: %q (%d)", long, len(long))
	}
}
