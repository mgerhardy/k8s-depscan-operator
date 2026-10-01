package controller

import (
	"context"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
	"github.com/mgerhardy/k8s-depscan-operator/internal/naming"
)

func reportReconcilerScheme() *runtime.Scheme {
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
	c := fake.NewClientBuilder().WithScheme(reportReconcilerScheme()).
		WithObjects(rep).WithStatusSubresource(rep).Build()

	r := &DepScanReportReconciler{Client: c, Config: &ConfigResolver{Client: c}, OperatorNamespace: "depscan-system"}
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
	c := fake.NewClientBuilder().WithScheme(reportReconcilerScheme()).
		WithObjects(rep).WithStatusSubresource(rep).Build()

	// Resolver with kube-system excluded.
	res := &ConfigResolver{Client: c}
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
	c := fake.NewClientBuilder().WithScheme(reportReconcilerScheme()).
		WithObjects(rep, activeJob).WithStatusSubresource(rep).Build()

	res := &ConfigResolver{Client: c}
	res.spec = depscanv1alpha1.DepScanConfigSpec{MaxConcurrentScans: 1}

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
	err = c.Get(context.Background(), types.NamespacedName{Namespace: "depscan-system", Name: naming.JobName("app:1")}, &job)
	if !apierrors.IsNotFound(err) {
		t.Errorf("scan job should not be created at capacity, got err=%v", err)
	}
	// Report stays Pending (empty phase), not Scanning.
	var got depscanv1alpha1.DepScanReport
	_ = c.Get(context.Background(), req.NamespacedName, &got)
	if got.Status.Phase == depscanv1alpha1.PhaseScanning {
		t.Error("report should not advance to Scanning while at capacity")
	}
}
