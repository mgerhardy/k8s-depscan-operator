package scan

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
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
