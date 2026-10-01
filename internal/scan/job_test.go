package scan

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
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

func TestBuildJob_PinnedVDBVersion(t *testing.T) {
	job := BuildJob(JobConfig{
		Image: "app:1", ScannerImage: "scanner", Namespace: "depscan-system",
		VDBClaim: "cache", VDBVersion: "vdbxz-app-2026-10-06", Scope: "app",
	})
	if job.Spec.Template.Labels[depscanv1alpha1.LabelVDBVersion] != "vdbxz-app-2026-10-06" {
		t.Errorf("scan job missing vdb-version label: %v", job.Spec.Template.Labels)
	}
	c := job.Spec.Template.Spec.Containers[0]
	// The version directory is mounted read-only.
	var mounted bool
	for _, m := range c.VolumeMounts {
		if m.Name == "vdb" {
			mounted = m.SubPath == "vdbxz-app-2026-10-06" && m.ReadOnly
		}
	}
	if !mounted {
		t.Errorf("vdb must be mounted read-only at the version subPath: %v", c.VolumeMounts)
	}
	// The scan must resolve the same scope the cache was primed with, and must
	// not re-download onto the read-only mount on staleness.
	if script := strings.Join(c.Command, " "); !strings.Contains(script, "--vdb-scope app") {
		t.Errorf("scan should pass --vdb-scope app; script=%q", script)
	}
	if !hasEnv(c, "VDB_AGE_HOURS") {
		t.Errorf("pinned read-only scan should set VDB_AGE_HOURS; env=%v", c.Env)
	}
}

func TestBuildJob_UnpinnedVDB(t *testing.T) {
	job := BuildJob(JobConfig{Image: "app:1", ScannerImage: "scanner", Namespace: "depscan-system"})
	if _, ok := job.Spec.Template.Labels[depscanv1alpha1.LabelVDBVersion]; ok {
		t.Error("unpinned scan should not carry a vdb-version label")
	}
	for _, v := range job.Spec.Template.Spec.Volumes {
		if v.Name == "vdb" && v.EmptyDir == nil {
			t.Error("unpinned scan should use an emptyDir vdb volume")
		}
	}
	c := job.Spec.Template.Spec.Containers[0]
	if strings.Contains(strings.Join(c.Command, " "), "--vdb-scope") {
		t.Error("unpinned scan should not pass --vdb-scope")
	}
	if hasEnv(c, "VDB_AGE_HOURS") {
		t.Error("unpinned scan should not override VDB_AGE_HOURS")
	}
}

func hasEnv(c corev1.Container, name string) bool {
	for _, e := range c.Env {
		if e.Name == name {
			return true
		}
	}
	return false
}

func TestBuildJob_DockerConfigSecret(t *testing.T) {
	job := BuildJob(JobConfig{
		Image:              "private.reg/app:latest",
		ScannerImage:       "ghcr.io/owasp-dep-scan/dep-scan:latest",
		Namespace:          "depscan-system",
		DockerConfigSecret: "app-regcred",
	})
	spec := job.Spec.Template.Spec

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
	if !hasEnv(spec.InitContainers[0], "DOCKER_CONFIG") {
		t.Error("crane init missing DOCKER_CONFIG env")
	}

	// Without credentials the pull is anonymous.
	anon := BuildJob(JobConfig{Image: "public.reg/app:latest", ScannerImage: "scanner", Namespace: "depscan-system"})
	for _, v := range anon.Spec.Template.Spec.Volumes {
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
