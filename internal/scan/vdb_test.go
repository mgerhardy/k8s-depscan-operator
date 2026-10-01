package scan

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
)

func TestBuildPrimeJob(t *testing.T) {
	job := BuildPrimeJob(PrimeJobConfig{
		ScannerImage: "scanner", Namespace: "depscan-system", VDBClaim: "depscan-vdb-cache",
	})
	if job.Name != VDBPrimeJobName {
		t.Errorf("name = %q", job.Name)
	}
	spec := job.Spec.Template.Spec
	if spec.AutomountServiceAccountToken == nil || *spec.AutomountServiceAccountToken {
		t.Error("prime pod must not automount SA token")
	}
	// Mounts the cache PVC at the cache root (writable, no subpath).
	var mounted bool
	for _, v := range spec.Volumes {
		if v.Name == "vdb" && v.PersistentVolumeClaim != nil && v.PersistentVolumeClaim.ClaimName == "depscan-vdb-cache" {
			mounted = true
		}
	}
	if !mounted {
		t.Error("prime job must mount the cache PVC")
	}
	script := strings.Join(spec.Containers[0].Command, " ")
	if !strings.Contains(script, "depscan-vdb download") || !strings.Contains(script, "mv ") || !strings.Contains(script, "latest.meta") {
		t.Errorf("prime script missing download/atomic-move/pointer steps: %q", script)
	}
	// Progress watcher: background download + periodic size reporting so users
	// can gauge how long the multi-GB pull will take.
	if !strings.Contains(script, "downloading...") || !strings.Contains(script, "du -sh") {
		t.Errorf("prime script should emit periodic download progress: %q", script)
	}
	// No override by default: the prime container carries no VDB_DATABASE_URL.
	for _, e := range spec.Containers[0].Env {
		if e.Name == "VDB_DATABASE_URL" {
			t.Errorf("unexpected VDB_DATABASE_URL env without an override: %q", e.Value)
		}
	}
	// No scope flag by default (dep-scan defaults to app+os).
	if strings.Contains(script, "--scope") {
		t.Errorf("prime script should not pin a scope by default: %q", script)
	}
}

func TestBuildPrimeJob_Scope(t *testing.T) {
	job := BuildPrimeJob(PrimeJobConfig{
		ScannerImage: "scanner", Namespace: "depscan-system", VDBClaim: "cache",
		Scope: "app",
	})
	script := strings.Join(job.Spec.Template.Spec.Containers[0].Command, " ")
	if !strings.Contains(script, "depscan-vdb download --scope app") {
		t.Errorf("prime script should pass --scope app: %q", script)
	}
}

func TestBuildPrimeJob_ReusesCachedVersion(t *testing.T) {
	// Without Force the prime short-circuits on an intact latest.meta.
	job := BuildPrimeJob(PrimeJobConfig{
		ScannerImage: "scanner", Namespace: "depscan-system", VDBClaim: "cache",
	})
	script := strings.Join(job.Spec.Template.Spec.Containers[0].Command, " ")
	if !strings.Contains(script, "reusing cached version") {
		t.Errorf("prime should reuse an intact cached version: %q", script)
	}
}

func TestBuildPrimeJob_ReportsVersionViaTerminationMessage(t *testing.T) {
	job := BuildPrimeJob(PrimeJobConfig{ScannerImage: "scanner", Namespace: "ns", VDBClaim: "cache"})
	c := job.Spec.Template.Spec.Containers[0]
	script := strings.Join(c.Command, " ")
	if strings.Count(script, "/dev/termination-log") < 2 {
		t.Errorf("both the reuse and publish paths must write the termination message: %q", script)
	}
	if c.Name != PrimeContainerName || c.TerminationMessagePolicy != corev1.TerminationMessageReadFile {
		t.Errorf("unexpected container %q / policy %q", c.Name, c.TerminationMessagePolicy)
	}
}

func TestBuildVDBGCJob_KeepsPointerTarget(t *testing.T) {
	job := BuildVDBGCJob(VDBGCJobConfig{ScannerImage: "scanner", Namespace: "ns", VDBClaim: "cache", KeepVersions: []string{"a"}})
	script := strings.Join(job.Spec.Template.Spec.Containers[0].Command, " ")
	if !strings.Contains(script, "cat latest.meta") || !strings.Contains(script, `"$name" = "$ptr"`) {
		t.Errorf("GC must always keep the version latest.meta names: %q", script)
	}
}

func TestBuildPrimeJob_ForceSkipsReuse(t *testing.T) {
	job := BuildPrimeJob(PrimeJobConfig{
		ScannerImage: "scanner", Namespace: "depscan-system", VDBClaim: "cache", Force: true,
	})
	script := strings.Join(job.Spec.Template.Spec.Containers[0].Command, " ")
	if strings.Contains(script, "reusing cached version") {
		t.Errorf("a forced prime must always download: %q", script)
	}
	if !strings.Contains(script, "depscan-vdb download") {
		t.Errorf("forced prime should download: %q", script)
	}
}

func TestBuildPrimeJob_DownloadURLOverride(t *testing.T) {
	const url = "registry.example.com/vdb/vdbxz:v6.7"
	job := BuildPrimeJob(PrimeJobConfig{
		ScannerImage: "scanner", Namespace: "depscan-system", VDBClaim: "cache",
		DownloadURL: url,
	})
	var got string
	for _, e := range job.Spec.Template.Spec.Containers[0].Env {
		if e.Name == "VDB_DATABASE_URL" {
			got = e.Value
		}
	}
	if got != url {
		t.Errorf("VDB_DATABASE_URL = %q, want %q", got, url)
	}
}

func TestBuildVDBGCJob(t *testing.T) {
	job := BuildVDBGCJob(VDBGCJobConfig{
		ScannerImage: "scanner", Namespace: "depscan-system", VDBClaim: "c",
		KeepVersions: []string{"v6.7-appos-2026-10-06", "v6.7-appos-2026-10-05"},
	})
	script := strings.Join(job.Spec.Template.Spec.Containers[0].Command, " ")
	if !strings.Contains(script, "v6.7-appos-2026-10-06") || !strings.Contains(script, "v6.7-appos-2026-10-05") {
		t.Errorf("gc keep-list not embedded: %q", script)
	}
	if !strings.Contains(script, ".tmp-*") || !strings.Contains(script, "rm -rf") {
		t.Errorf("gc script must skip temp dirs and delete stale ones: %q", script)
	}
}

func TestBuildJob_PinsVDBVersion(t *testing.T) {
	job := BuildJob(JobConfig{
		Image: "app:1", ScannerImage: "scanner", Namespace: "depscan-system",
		VDBClaim: "cache", VDBVersion: "v6.7-appos-2026-10-06",
	})
	// Version label present.
	if job.Spec.Template.Labels[depscanv1alpha1.LabelVDBVersion] != "v6.7-appos-2026-10-06" {
		t.Errorf("scan job missing vdb-version label: %v", job.Spec.Template.Labels)
	}
	// VDB mount uses the version subPath, read-only.
	var found bool
	for _, c := range job.Spec.Template.Spec.Containers {
		for _, m := range c.VolumeMounts {
			if m.Name == "vdb" {
				found = true
				if m.SubPath != "v6.7-appos-2026-10-06" {
					t.Errorf("vdb mount subPath = %q, want version", m.SubPath)
				}
				if !m.ReadOnly {
					t.Error("vdb mount should be read-only when pinned")
				}
			}
		}
	}
	if !found {
		t.Error("vdb mount not found")
	}
}

func TestBuildJob_NoVDBVersionWhenUnpinned(t *testing.T) {
	job := BuildJob(JobConfig{Image: "app:1", ScannerImage: "scanner", Namespace: "depscan-system"})
	if _, ok := job.Spec.Template.Labels[depscanv1alpha1.LabelVDBVersion]; ok {
		t.Error("unpinned scan should not carry a vdb-version label")
	}
	// Falls back to an emptyDir vdb volume.
	for _, v := range job.Spec.Template.Spec.Volumes {
		if v.Name == "vdb" && v.EmptyDir == nil {
			t.Error("unpinned scan should use an emptyDir vdb volume")
		}
	}
	_ = corev1.Volume{}
}
