package scan

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestBuildJob_CraneInitAndScan(t *testing.T) {
	job := BuildJob(JobConfig{
		Image:        "registry.example.com/app:1.2.3",
		ScannerImage: "ghcr.io/owasp-dep-scan/dep-scan:latest",
		Namespace:    "depscan-system",
		TTLSeconds:   600,
		VDBClaim:     "depscan-vdb-cache",
	})

	spec := job.Spec.Template.Spec

	// Exactly one init container (fetch) with no pull secrets.
	if len(spec.InitContainers) != 1 {
		t.Fatalf("init containers = %d, want 1", len(spec.InitContainers))
	}
	fetch := spec.InitContainers[0]
	if fetch.Name != "fetch-image" {
		t.Errorf("init container name = %q", fetch.Name)
	}
	if !strings.Contains(strings.Join(fetch.Command, " "), "crane") &&
		!strings.Contains(fetch.Image, "crane") {
		t.Errorf("fetch should use crane: image=%q cmd=%v", fetch.Image, fetch.Command)
	}
	// crane pulls the exact image to the shared tarball path.
	cmd := strings.Join(fetch.Command, " ")
	if !strings.Contains(cmd, "registry.example.com/app:1.2.3") || !strings.Contains(cmd, imageTar) {
		t.Errorf("crane command missing image or tar path: %q", cmd)
	}

	// dep-scan container scans the local tarball, not the remote ref.
	if len(spec.Containers) != 1 {
		t.Fatalf("containers = %d, want 1", len(spec.Containers))
	}
	ds := spec.Containers[0]
	script := strings.Join(ds.Command, " ")
	if !strings.Contains(script, "depscan --src "+imageTar) {
		t.Errorf("dep-scan should scan the local tarball; script=%q", script)
	}
	if !strings.Contains(script, "--csaf") {
		t.Errorf("dep-scan should request CSAF output")
	}
	// A dep-scan failure must fail the Job, not be swallowed into a clean report.
	if !strings.Contains(script, "rc=$?") || !strings.Contains(script, "exit \"$rc\"") {
		t.Errorf("scan script must propagate dep-scan's exit code; script=%q", script)
	}

	// VDB claim is mounted.
	foundVDB := false
	for _, v := range spec.Volumes {
		if v.Name == "vdb" && v.PersistentVolumeClaim != nil && v.PersistentVolumeClaim.ClaimName == "depscan-vdb-cache" {
			foundVDB = true
		}
	}
	if !foundVDB {
		t.Errorf("vdb PVC volume not wired")
	}
}

func TestBuildJob_ScopeMatchesPrimedCache(t *testing.T) {
	job := BuildJob(JobConfig{
		Image: "app:1", ScannerImage: "scanner", Namespace: "depscan-system",
		VDBClaim: "cache", VDBVersion: "vdbxz-app-2026-10-06", Scope: "app",
	})
	c := job.Spec.Template.Spec.Containers[0]
	script := strings.Join(c.Command, " ")
	// The scan must resolve the same scope the cache was primed with.
	if !strings.Contains(script, "--vdb-scope app") {
		t.Errorf("scan should pass --vdb-scope app; script=%q", script)
	}
	// With a pinned read-only version, dep-scan must not re-download on staleness.
	var ageSet bool
	for _, e := range c.Env {
		if e.Name == "VDB_AGE_HOURS" {
			ageSet = true
		}
	}
	if !ageSet {
		t.Errorf("pinned read-only scan should set VDB_AGE_HOURS to avoid stale re-download; env=%v", c.Env)
	}
}

func TestBuildJob_NoScopeFlagOrAgeWhenUnpinned(t *testing.T) {
	job := BuildJob(JobConfig{Image: "app:1", ScannerImage: "scanner", Namespace: "depscan-system"})
	c := job.Spec.Template.Spec.Containers[0]
	if strings.Contains(strings.Join(c.Command, " "), "--vdb-scope") {
		t.Error("unpinned scan should not pass --vdb-scope")
	}
	for _, e := range c.Env {
		if e.Name == "VDB_AGE_HOURS" {
			t.Error("unpinned scan should not override VDB_AGE_HOURS")
		}
	}
}

func TestBuildJob_DockerConfigSecret(t *testing.T) {
	job := BuildJob(JobConfig{
		Image:              "private.reg/app:latest",
		ScannerImage:       "ghcr.io/owasp-dep-scan/dep-scan:latest",
		Namespace:          "depscan-system",
		DockerConfigSecret: "app-regcred",
	})
	spec := job.Spec.Template.Spec

	// Only the crane fetch init container (no prep step).
	if len(spec.InitContainers) != 1 || spec.InitContainers[0].Name != "fetch-image" {
		t.Fatalf("init containers = %v, want just fetch-image", spec.InitContainers)
	}
	// The dockercfg secret is mounted and DOCKER_CONFIG points at it.
	var mountsSecret bool
	for _, v := range spec.Volumes {
		if v.Name == "dockercfg" && v.Secret != nil && v.Secret.SecretName == "app-regcred" {
			mountsSecret = true
		}
	}
	if !mountsSecret {
		t.Error("dockercfg secret volume not wired to the provided secret")
	}
	fetch := spec.InitContainers[0]
	var hasEnv bool
	for _, e := range fetch.Env {
		if e.Name == "DOCKER_CONFIG" && e.Value == dockerCfg {
			hasEnv = true
		}
	}
	if !hasEnv {
		t.Error("crane init missing DOCKER_CONFIG env")
	}
}

func TestBuildJob_AnonymousPull(t *testing.T) {
	job := BuildJob(JobConfig{
		Image:        "public.reg/app:latest",
		ScannerImage: "scanner",
		Namespace:    "depscan-system",
	})
	for _, v := range job.Spec.Template.Spec.Volumes {
		if v.Name == "dockercfg" {
			t.Error("no dockercfg volume expected without credentials")
		}
	}
}

func TestBuildJob_Hardening(t *testing.T) {
	job := BuildJob(JobConfig{
		Image:              "private.reg/app:latest",
		ScannerImage:       "ghcr.io/owasp-dep-scan/dep-scan:latest",
		Namespace:          "depscan-system",
		DockerConfigSecret: "app-regcred",
	})
	spec := job.Spec.Template.Spec

	if spec.AutomountServiceAccountToken == nil || *spec.AutomountServiceAccountToken {
		t.Error("scan pod must not automount the ServiceAccount token")
	}
	if spec.SecurityContext == nil || spec.SecurityContext.SeccompProfile == nil ||
		spec.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Error("pod should set seccompProfile RuntimeDefault")
	}

	all := append([]corev1.Container{}, spec.InitContainers...)
	all = append(all, spec.Containers...)
	for _, c := range all {
		sc := c.SecurityContext
		if sc == nil {
			t.Fatalf("container %s has no securityContext", c.Name)
		}
		if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
			t.Errorf("container %s should block privilege escalation", c.Name)
		}
		if sc.Capabilities == nil || len(sc.Capabilities.Drop) == 0 || sc.Capabilities.Drop[0] != "ALL" {
			t.Errorf("container %s should drop ALL capabilities", c.Name)
		}
	}
}

func TestBuildJob_Profile(t *testing.T) {
	job := BuildJob(JobConfig{
		Image: "app:1", ScannerImage: "scanner", Namespace: "depscan-system", Profile: "generic",
	})
	script := strings.Join(job.Spec.Template.Spec.Containers[0].Command, " ")
	if !strings.Contains(script, "--profile generic") {
		t.Errorf("scan command missing configured profile; got %q", script)
	}

	def := BuildJob(JobConfig{Image: "app:1", ScannerImage: "scanner", Namespace: "depscan-system"})
	defScript := strings.Join(def.Spec.Template.Spec.Containers[0].Command, " ")
	if !strings.Contains(defScript, "--profile research") {
		t.Errorf("profile should default to research; got %q", defScript)
	}
}

func TestBuildJob_DefaultCraneImageAndPlatform(t *testing.T) {
	job := BuildJob(JobConfig{
		Image:        "app:latest",
		ScannerImage: "scanner",
		Namespace:    "depscan-system",
	})
	fetch := job.Spec.Template.Spec.InitContainers[0]
	if fetch.Image != DefaultCraneImage {
		t.Errorf("crane image = %q, want default %q", fetch.Image, DefaultCraneImage)
	}
	if !strings.Contains(strings.Join(fetch.Command, " "), "linux/amd64") {
		t.Errorf("default platform linux/amd64 not applied: %v", fetch.Command)
	}
}

func TestBuildJob_MarkerNonce(t *testing.T) {
	job := BuildJob(JobConfig{Image: "app:1", ScannerImage: "s", Namespace: "ns", MarkerNonce: "abc"})
	if job.Annotations[AnnotationMarkerNonce] != "abc" {
		t.Errorf("nonce annotation missing: %v", job.Annotations)
	}
	script := strings.Join(job.Spec.Template.Spec.Containers[0].Command, " ")
	vb, _, _, ce := Markers("abc")
	if !strings.Contains(script, vb) || !strings.Contains(script, ce) {
		t.Errorf("script should use nonce markers: %q", script)
	}
}

func TestBuildJob_ImageNotInScriptText(t *testing.T) {
	const img = "registry.example.com/team/app:1.2.3"
	job := BuildJob(JobConfig{Image: img, ScannerImage: "s", Namespace: "ns"})
	c := job.Spec.Template.Spec.Containers[0]
	if strings.Contains(strings.Join(c.Command, " "), img) {
		t.Error("image reference must not be interpolated into the shell script")
	}
	var env string
	for _, e := range c.Env {
		if e.Name == "SCAN_IMAGE" {
			env = e.Value
		}
	}
	if env != img {
		t.Errorf("SCAN_IMAGE = %q, want %q", env, img)
	}
	crane := job.Spec.Template.Spec.InitContainers[0].Command
	if len(crane) < 2 || crane[len(crane)-3] != "--" || crane[len(crane)-2] != img {
		t.Errorf("crane args should end flags before the image: %v", crane)
	}
}

func TestBuildJob_DeadlineAndScratchLimit(t *testing.T) {
	limit := resource.MustParse("5Gi")
	job := BuildJob(JobConfig{Image: "app:1", ScannerImage: "s", Namespace: "ns", Timeout: time.Hour, WorkSizeLimit: &limit})
	if d := job.Spec.ActiveDeadlineSeconds; d == nil || *d != 3600 {
		t.Errorf("activeDeadlineSeconds = %v, want 3600", d)
	}
	for _, v := range job.Spec.Template.Spec.Volumes {
		if v.Name == "work" && (v.EmptyDir == nil || v.EmptyDir.SizeLimit == nil || v.EmptyDir.SizeLimit.Cmp(limit) != 0) {
			t.Errorf("work volume should be size-limited: %+v", v.EmptyDir)
		}
	}
}
