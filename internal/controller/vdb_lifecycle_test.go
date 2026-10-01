package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
	"github.com/mgerhardy/k8s-depscan-operator/internal/scan"
)

func scanJob(name, version string, succeeded, failed int32) *batchv1.Job {
	j := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "depscan-system",
			Labels: map[string]string{
				depscanv1alpha1.LabelManagedBy:  depscanv1alpha1.ManagedByValue,
				depscanv1alpha1.LabelVDBVersion: version,
			},
		},
	}
	j.Status.Succeeded = succeeded
	j.Status.Failed = failed
	return j
}

func TestVersionsInUse(t *testing.T) {
	active := scanJob("scan-active", "v6.7-appos-2026-10-06", 0, 0)
	done := scanJob("scan-done", "v6.7-appos-2026-10-05", 1, 0)
	retrying := scanJob("scan-retrying", "v6.7-appos-2026-10-04", 0, 1) // backoffLimit not yet exhausted
	limit := int32(1)
	retrying.Spec.BackoffLimit = &limit
	c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(active, done, retrying).Build()
	r := &DepScanReportReconciler{Client: c, OperatorNamespace: "depscan-system"}

	inUse, err := r.versionsInUse(context.Background(), "depscan-system")
	if err != nil {
		t.Fatal(err)
	}
	if !inUse["v6.7-appos-2026-10-06"] {
		t.Error("active job's version should be in use")
	}
	if !inUse["v6.7-appos-2026-10-04"] {
		t.Error("a retrying job's version should be in use")
	}
	if inUse["v6.7-appos-2026-10-05"] {
		t.Error("finished job's version must not be considered in use")
	}
}

func TestEnsureVDBReady_DisabledIsReadyNoVersion(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme()).Build()
	r := &DepScanReportReconciler{Client: c, Config: &ConfigResolver{Client: c, loaded: true}, OperatorNamespace: "depscan-system"}
	got, err := r.ensureVDBReady(context.Background(), depscanv1alpha1.DepScanConfigSpec{}, "depscan-system")
	if err != nil {
		t.Fatal(err)
	}
	if !got.ready || got.version != "" {
		t.Errorf("cache disabled should be ready with empty version, got %+v", got)
	}
}

func vdbEnabledCfg() depscanv1alpha1.DepScanConfigSpec {
	return depscanv1alpha1.DepScanConfigSpec{
		ScannerImage: "scanner",
		VDBCache: &depscanv1alpha1.VDBCacheSpec{
			Enabled: true, ClaimName: "cache",
			RefreshInterval: metav1.Duration{Duration: time.Hour},
		},
	}
}

func primeScript(t *testing.T, c client.Client) string {
	t.Helper()
	var job batchv1.Job
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "depscan-system", Name: scan.VDBPrimeJobName}, &job); err != nil {
		t.Fatalf("prime job not created: %v", err)
	}
	return strings.Join(job.Spec.Template.Spec.Containers[0].Command, " ")
}

func TestEnsureVDBReady_FirstPrimeReusesCache(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme()).Build()
	r := &DepScanReportReconciler{Client: c, OperatorNamespace: "depscan-system"}
	got, err := r.ensureVDBReady(context.Background(), vdbEnabledCfg(), "depscan-system")
	if err != nil {
		t.Fatal(err)
	}
	if got.ready {
		t.Error("no version yet: must not be ready")
	}
	if !strings.Contains(primeScript(t, c), "reusing cached version") {
		t.Error("first prime (e.g. after restart) should reuse an intact cached version")
	}
}

func TestEnsureVDBReady_DueRefreshForcesDownload(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme()).Build()
	r := &DepScanReportReconciler{Client: c, OperatorNamespace: "depscan-system"}
	r.vdbStateNS = "depscan-system"
	r.vdbLatest = "vdb-2026-10-01"
	r.vdbLastPrimedAt = time.Now().Add(-2 * time.Hour)

	got, err := r.ensureVDBReady(context.Background(), vdbEnabledCfg(), "depscan-system")
	if err != nil {
		t.Fatal(err)
	}
	if !got.ready || got.version != "vdb-2026-10-01" {
		t.Errorf("should keep serving the current version during refresh, got %+v", got)
	}
	if strings.Contains(primeScript(t, c), "reusing cached version") {
		t.Error("a due refresh must force a download")
	}
}

func TestEnsureVDBReady_FailedPrimeBacksOff(t *testing.T) {
	failed := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: scan.VDBPrimeJobName, Namespace: "depscan-system"}}
	failed.Status.Failed = 3
	failed.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue}}
	c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(failed).Build()
	r := &DepScanReportReconciler{Client: c, OperatorNamespace: "depscan-system"}
	ctx := context.Background()

	if _, err := r.ensureVDBReady(ctx, vdbEnabledCfg(), "depscan-system"); err != nil {
		t.Fatal(err)
	}
	// The failed Job is reaped, but no new prime starts during the backoff.
	if _, err := r.ensureVDBReady(ctx, vdbEnabledCfg(), "depscan-system"); err != nil {
		t.Fatal(err)
	}
	var job batchv1.Job
	err := c.Get(ctx, types.NamespacedName{Namespace: "depscan-system", Name: scan.VDBPrimeJobName}, &job)
	if !apierrors.IsNotFound(err) {
		t.Errorf("prime must not be recreated during backoff, got err=%v", err)
	}
}

func TestEnsureVDBReady_RetryingPrimeKeepsRunning(t *testing.T) {
	limit := int32(2)
	retrying := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: scan.VDBPrimeJobName, Namespace: "depscan-system"},
		Spec:       batchv1.JobSpec{BackoffLimit: &limit},
	}
	retrying.Status.Failed = 1
	c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(retrying).Build()
	r := &DepScanReportReconciler{Client: c, OperatorNamespace: "depscan-system"}
	ctx := context.Background()

	if _, err := r.ensureVDBReady(ctx, vdbEnabledCfg(), "depscan-system"); err != nil {
		t.Fatal(err)
	}
	var job batchv1.Job
	if err := c.Get(ctx, types.NamespacedName{Namespace: "depscan-system", Name: scan.VDBPrimeJobName}, &job); err != nil {
		t.Errorf("a prime Job still within its backoffLimit must not be deleted, got err=%v", err)
	}
	if r.vdbPrimeFailures != 0 {
		t.Errorf("a pod retry is not a failed prime, failures=%d", r.vdbPrimeFailures)
	}
}

func TestPrimeBackoff(t *testing.T) {
	cases := map[int]time.Duration{1: time.Minute, 2: 2 * time.Minute, 3: 4 * time.Minute, 20: time.Hour}
	for n, want := range cases {
		if got := primeBackoff(n); got != want {
			t.Errorf("primeBackoff(%d) = %v, want %v", n, got, want)
		}
	}
}

// succeededPrime returns a finished prime Job plus its pod reporting version
// via the termination message.
func succeededPrime(version string, completed time.Time) (*batchv1.Job, *corev1.Pod) {
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: scan.VDBPrimeJobName, Namespace: "depscan-system"}}
	job.Status.Succeeded = 1
	job.Status.CompletionTime = &metav1.Time{Time: completed}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "prime-pod", Namespace: "depscan-system",
		Labels: map[string]string{"job-name": scan.VDBPrimeJobName},
	}}
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name:  scan.PrimeContainerName,
		State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0, Message: version}},
	}}
	return job, pod
}

func TestEnsureVDBReady_PersistsPrimedState(t *testing.T) {
	completed := time.Now().Add(-time.Minute).Truncate(time.Second)
	job, pod := succeededPrime("vdb-2026-10-06", completed)
	c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(job, pod).Build()
	r := &DepScanReportReconciler{Client: c, OperatorNamespace: "depscan-system"}
	ctx := context.Background()

	got, err := r.ensureVDBReady(ctx, vdbEnabledCfg(), "depscan-system")
	if err != nil {
		t.Fatal(err)
	}
	if !got.ready || got.version != "vdb-2026-10-06" {
		t.Fatalf("want ready with primed version, got %+v", got)
	}
	var cm corev1.ConfigMap
	if err := c.Get(ctx, types.NamespacedName{Namespace: "depscan-system", Name: vdbStateConfigMap}, &cm); err != nil {
		t.Fatalf("state not persisted: %v", err)
	}
	if cm.Data["version"] != "vdb-2026-10-06" || cm.Data["primedAt"] != completed.UTC().Format(time.RFC3339) {
		t.Errorf("unexpected persisted state %v", cm.Data)
	}

	// A restarted operator (fresh reconciler) resumes from the persisted state
	// without starting a prime.
	_ = c.Delete(ctx, job)
	r2 := &DepScanReportReconciler{Client: c, OperatorNamespace: "depscan-system"}
	got, err = r2.ensureVDBReady(ctx, vdbEnabledCfg(), "depscan-system")
	if err != nil {
		t.Fatal(err)
	}
	if !got.ready || got.version != "vdb-2026-10-06" {
		t.Errorf("restart should resume persisted version, got %+v", got)
	}
	var prime batchv1.Job
	if err := c.Get(ctx, types.NamespacedName{Namespace: "depscan-system", Name: scan.VDBPrimeJobName}, &prime); !apierrors.IsNotFound(err) {
		t.Errorf("restart within the refresh interval must not prime, got err=%v", err)
	}
}

func TestEnsureVDBReady_RejectsMalformedVersion(t *testing.T) {
	job, pod := succeededPrime("../../etc", time.Now())
	c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(job, pod).Build()
	r := &DepScanReportReconciler{Client: c, OperatorNamespace: "depscan-system"}
	got, err := r.ensureVDBReady(context.Background(), vdbEnabledCfg(), "depscan-system")
	if err != nil {
		t.Fatal(err)
	}
	if got.ready {
		t.Errorf("malformed version key must not become current, got %+v", got)
	}
}

func TestGCSkipsWhilePrimeJobExists(t *testing.T) {
	running := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: scan.VDBPrimeJobName, Namespace: "depscan-system"}}
	c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(running).Build()
	r := &DepScanReportReconciler{Client: c, OperatorNamespace: "depscan-system"}
	r.vdbStateNS, r.vdbLatest = "depscan-system", "vdb-2026-10-01"

	r.gcVDBVersions(context.Background(), vdbEnabledCfg(), "depscan-system")
	var gc batchv1.Job
	err := c.Get(context.Background(), types.NamespacedName{Namespace: "depscan-system", Name: scan.VDBGCJobName}, &gc)
	if !apierrors.IsNotFound(err) {
		t.Errorf("GC must not run while a prime Job exists, got err=%v", err)
	}
}

func TestDeletedStateConfigMapForcesRefresh(t *testing.T) {
	// The prime Job that produced the current version is still around (within
	// its TTL); it must not count as satisfying the refresh.
	completed := time.Now().Add(-time.Minute)
	job, pod := succeededPrime("vdb-2026-10-01", completed)
	c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(job, pod).Build()
	r := &DepScanReportReconciler{Client: c, OperatorNamespace: "depscan-system"}
	r.vdbStateNS, r.vdbLatest, r.vdbLastPrimedAt = "depscan-system", "vdb-2026-10-01", completed

	ctx := context.Background()
	r.checkRefreshRequested(ctx, "depscan-system")
	for range 2 { // the first pass replaces the old Job, the second starts the prime
		if _, err := r.ensureVDBReady(ctx, vdbEnabledCfg(), "depscan-system"); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Contains(primeScript(t, c), "reusing cached version") {
		t.Error("deleting the state ConfigMap should force a fresh download")
	}
}
