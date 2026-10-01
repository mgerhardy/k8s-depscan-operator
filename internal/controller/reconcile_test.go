package controller

import (
	"context"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
	"github.com/mgerhardy/k8s-depscan-operator/internal/naming"
	"github.com/mgerhardy/k8s-depscan-operator/internal/scan"
)

// testScheme registers the core and depscan types for fake clients.
func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = depscanv1alpha1.AddToScheme(s)
	return s
}

func TestReconcilePendingStartsScan(t *testing.T) {
	rep := &depscanv1alpha1.DepScanReport{
		ObjectMeta: metav1.ObjectMeta{Name: naming.ReportName("nginx:1.25"), Namespace: "prod"},
		Spec:       depscanv1alpha1.DepScanReportSpec{Image: "nginx:1.25"},
	}
	c := fake.NewClientBuilder().WithScheme(testScheme()).
		WithObjects(rep).WithStatusSubresource(rep).Build()

	res := &ConfigResolver{Client: c, loaded: true}
	res.spec = depscanv1alpha1.DepScanConfigSpec{VDBCache: &depscanv1alpha1.VDBCacheSpec{Enabled: false}}
	r := &DepScanReportReconciler{Client: c, Config: res, OperatorNamespace: "depscan-system"}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "prod", Name: rep.Name}}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// Report should now be Scanning with a job name recorded.
	var got depscanv1alpha1.DepScanReport
	if err := c.Get(context.Background(), req.NamespacedName, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase != depscanv1alpha1.PhaseScanning {
		t.Errorf("phase = %q, want Scanning", got.Status.Phase)
	}
	if got.Status.ScanJob == "" {
		t.Error("scan job name not recorded")
	}

	// A scan Job should exist in the operator namespace.
	var job batchv1.Job
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "depscan-system", Name: got.Status.ScanJob}, &job); err != nil {
		t.Fatalf("scan job not created: %v", err)
	}
	if len(job.Spec.Template.Spec.InitContainers) == 0 {
		t.Error("scan job missing crane init container")
	}
}

func TestReconcileOutOfScopeDeletesReport(t *testing.T) {
	rep := &depscanv1alpha1.DepScanReport{
		ObjectMeta: metav1.ObjectMeta{Name: naming.ReportName("redis:7"), Namespace: "kube-system"},
		Spec:       depscanv1alpha1.DepScanReportSpec{Image: "redis:7"},
	}
	c := fake.NewClientBuilder().WithScheme(testScheme()).
		WithObjects(rep).WithStatusSubresource(rep).Build()

	// Resolver with kube-system excluded.
	res := &ConfigResolver{Client: c, loaded: true}
	res.spec = depscanv1alpha1.DepScanConfigSpec{ExcludeNamespaces: []string{"kube-system"}}

	r := &DepScanReportReconciler{Client: c, Config: res, OperatorNamespace: "depscan-system"}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "kube-system", Name: rep.Name}}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var got depscanv1alpha1.DepScanReport
	err := c.Get(context.Background(), req.NamespacedName, &got)
	if !apierrors.IsNotFound(err) {
		t.Errorf("out-of-scope report should be deleted, got err=%v", err)
	}
}

func TestReconcileRespectsConcurrencyCap(t *testing.T) {
	rep := &depscanv1alpha1.DepScanReport{
		ObjectMeta: metav1.ObjectMeta{Name: naming.ReportName("app:1"), Namespace: "prod"},
		Spec:       depscanv1alpha1.DepScanReportSpec{Image: "app:1"},
	}
	// One active managed job already running, cap of 1.
	activeJob := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "depscan-existing",
			Namespace: "depscan-system",
			Labels:    map[string]string{depscanv1alpha1.LabelManagedBy: depscanv1alpha1.ManagedByValue},
		},
	}
	c := fake.NewClientBuilder().WithScheme(testScheme()).
		WithObjects(rep, activeJob).WithStatusSubresource(rep).Build()

	res := &ConfigResolver{Client: c, loaded: true}
	res.spec = depscanv1alpha1.DepScanConfigSpec{MaxConcurrentScans: 1, VDBCache: &depscanv1alpha1.VDBCacheSpec{Enabled: false}}

	r := &DepScanReportReconciler{Client: c, Config: res, OperatorNamespace: "depscan-system"}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "prod", Name: rep.Name}}
	gotRes, err := r.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if gotRes.RequeueAfter == 0 {
		t.Error("expected requeue when at scan capacity")
	}

	// No new job for this report should have been created.
	var job batchv1.Job
	err = c.Get(context.Background(), types.NamespacedName{Namespace: "depscan-system", Name: naming.JobName("prod", "app:1")}, &job)
	if !apierrors.IsNotFound(err) {
		t.Errorf("scan job should not be created at capacity, got err=%v", err)
	}
	// Report stays Pending (empty phase), not Scanning.
	var got depscanv1alpha1.DepScanReport
	_ = c.Get(context.Background(), req.NamespacedName, &got)
	if got.Status.Phase == depscanv1alpha1.PhaseScanning {
		t.Error("report should not advance to Scanning while at capacity")
	}
	if got.Status.Message != "queued: 1/1 scan slots in use (maxConcurrentScans)" {
		t.Errorf("queued report should explain why, message = %q", got.Status.Message)
	}
}

func TestVDBJobsDoNotTakeScanSlots(t *testing.T) {
	prime := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{
		Name: "depscan-vdb-prime", Namespace: "depscan-system",
		Labels: map[string]string{
			depscanv1alpha1.LabelManagedBy: depscanv1alpha1.ManagedByValue,
			depscanv1alpha1.LabelComponent: depscanv1alpha1.ComponentVDBPrime,
		},
	}}
	c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(prime).Build()
	r := &DepScanReportReconciler{Client: c, OperatorNamespace: "depscan-system"}
	active, err := r.activeScans(context.Background(), "depscan-system")
	if err != nil || active != 0 {
		t.Errorf("a running prime Job must not count as a scan, active=%d err=%v", active, err)
	}
}

func TestReportForJob(t *testing.T) {
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{
		depscanv1alpha1.LabelManagedBy: depscanv1alpha1.ManagedByValue,
		"depscan.io/report-namespace":  "prod",
		"depscan.io/report-name":       "r1",
	}}}
	reqs := reportForJob(context.Background(), job)
	if len(reqs) != 1 || reqs[0].Namespace != "prod" || reqs[0].Name != "r1" {
		t.Errorf("got %v", reqs)
	}
	if reqs := reportForJob(context.Background(), &batchv1.Job{}); len(reqs) != 0 {
		t.Errorf("unlabeled Job must not map to a report, got %v", reqs)
	}
}

func TestDefaultConfigUsesVDBCache(t *testing.T) {
	rep := &depscanv1alpha1.DepScanReport{
		ObjectMeta: metav1.ObjectMeta{Name: naming.ReportName("nginx:1.25"), Namespace: "prod"},
		Spec:       depscanv1alpha1.DepScanReportSpec{Image: "nginx:1.25"},
	}
	c := fake.NewClientBuilder().WithScheme(testScheme()).
		WithObjects(rep).WithStatusSubresource(rep).Build()
	// No DepScanConfig object: built-in defaults.
	res := &ConfigResolver{Client: c}
	if err := res.Load(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	r := &DepScanReportReconciler{Client: c, Config: res, OperatorNamespace: "depscan-system"}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "prod", Name: rep.Name}}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	var job batchv1.Job
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "depscan-system", Name: "depscan-vdb-prime"}, &job); err != nil {
		t.Errorf("defaults should prime the shared VDB cache instead of downloading per scan: %v", err)
	}
}

func TestUncachedScanBoundsVDBScratch(t *testing.T) {
	cfg := withDefaults(depscanv1alpha1.DepScanConfigSpec{VDBCache: &depscanv1alpha1.VDBCacheSpec{Enabled: false}})
	if cfg.VDBCache.Size != depscanv1alpha1.DefaultVDBCacheSize {
		t.Errorf("disabled cache should still carry the size bound, got %q", cfg.VDBCache.Size)
	}
}

func TestRescanAnnotation(t *testing.T) {
	now := metav1.Now()
	rep := &depscanv1alpha1.DepScanReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: naming.ReportName("app:1"), Namespace: "prod",
			Annotations: map[string]string{AnnotationRescan: "now"},
		},
		Spec:   depscanv1alpha1.DepScanReportSpec{Image: "app:1"},
		Status: depscanv1alpha1.DepScanReportStatus{Phase: depscanv1alpha1.PhaseCompleted, UpdateTimestamp: &now},
	}
	c := fake.NewClientBuilder().WithScheme(testScheme()).
		WithObjects(rep).WithStatusSubresource(rep).Build()
	r := &DepScanReportReconciler{Client: c, Config: &ConfigResolver{Client: c, loaded: true}, OperatorNamespace: "depscan-system"}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "prod", Name: rep.Name}}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	var got depscanv1alpha1.DepScanReport
	_ = c.Get(context.Background(), req.NamespacedName, &got)
	if got.Status.Phase != depscanv1alpha1.PhasePending {
		t.Errorf("phase = %q, want Pending", got.Status.Phase)
	}
	if _, ok := got.Annotations[AnnotationRescan]; ok {
		t.Error("rescan annotation should be consumed")
	}
}

// A rescan within the Job TTL must run a new scan, not re-ingest the old one.
func TestStartScanReplacesFinishedJob(t *testing.T) {
	rep := &depscanv1alpha1.DepScanReport{
		ObjectMeta: metav1.ObjectMeta{Name: naming.ReportName("app:1"), Namespace: "prod"},
		Spec:       depscanv1alpha1.DepScanReportSpec{Image: "app:1"},
		Status:     depscanv1alpha1.DepScanReportStatus{Phase: depscanv1alpha1.PhasePending},
	}
	old := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: naming.JobName("prod", "app:1"), Namespace: "depscan-system"}}
	old.Status.Succeeded = 1
	c := fake.NewClientBuilder().WithScheme(testScheme()).
		WithObjects(rep, old).WithStatusSubresource(rep).Build()
	res := &ConfigResolver{Client: c, loaded: true}
	res.spec = depscanv1alpha1.DepScanConfigSpec{VDBCache: &depscanv1alpha1.VDBCacheSpec{Enabled: false}}
	r := &DepScanReportReconciler{Client: c, Config: res, OperatorNamespace: "depscan-system"}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "prod", Name: rep.Name}}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(old), &batchv1.Job{}); !apierrors.IsNotFound(err) {
		t.Errorf("finished Job should be deleted, got err=%v", err)
	}
	var got depscanv1alpha1.DepScanReport
	_ = c.Get(context.Background(), req.NamespacedName, &got)
	if got.Status.Phase == depscanv1alpha1.PhaseScanning {
		t.Error("report must not adopt the finished Job")
	}
}

// Reports cannot own their cross-namespace scan Job and credentials, so a
// deleted report's are removed by the reconcile that observes the deletion.
func TestDeletedReportCleansUpScanResources(t *testing.T) {
	name := naming.ReportName("app:1")
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{
		Name: naming.JobName("prod", "app:1"), Namespace: "depscan-system",
		Labels: map[string]string{
			depscanv1alpha1.LabelManagedBy: depscanv1alpha1.ManagedByValue,
			scan.LabelReportNamespace:      "prod",
			scan.LabelReportName:           name,
		},
	}}
	creds := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: scanCredentialsSecretName("prod", name), Namespace: "depscan-system",
		Labels: map[string]string{depscanv1alpha1.LabelManagedBy: depscanv1alpha1.ManagedByValue},
	}}
	c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(job, creds).Build()
	r := &DepScanReportReconciler{Client: c, Config: &ConfigResolver{Client: c, loaded: true}, OperatorNamespace: "depscan-system"}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "prod", Name: name}}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(job), &batchv1.Job{}); !apierrors.IsNotFound(err) {
		t.Errorf("scan Job should be deleted, got err=%v", err)
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(creds), &corev1.Secret{}); !apierrors.IsNotFound(err) {
		t.Errorf("credentials Secret should be deleted, got err=%v", err)
	}
}
