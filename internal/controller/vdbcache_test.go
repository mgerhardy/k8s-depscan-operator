package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
)

func newFakeReconciler(objs ...runtime.Object) *DepScanReportReconciler {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = depscanv1alpha1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objs...).Build()
	return &DepScanReportReconciler{Client: c, OperatorNamespace: "depscan-system"}
}

func TestEnsureVDBClaim_Disabled(t *testing.T) {
	r := newFakeReconciler()
	name, err := r.ensureVDBClaim(context.Background(), depscanv1alpha1.DepScanConfigSpec{}, "depscan-system")
	if err != nil {
		t.Fatal(err)
	}
	if name != "" {
		t.Errorf("expected empty claim when cache disabled, got %q", name)
	}
}

func TestEnsureVDBClaim_ExplicitClaim(t *testing.T) {
	r := newFakeReconciler()
	cfg := depscanv1alpha1.DepScanConfigSpec{
		VDBCache: &depscanv1alpha1.VDBCacheSpec{Enabled: true, ClaimName: "my-cache"},
	}
	name, err := r.ensureVDBClaim(context.Background(), cfg, "depscan-system")
	if err != nil {
		t.Fatal(err)
	}
	if name != "my-cache" {
		t.Errorf("expected passthrough my-cache, got %q", name)
	}
	// No PVC should have been provisioned.
	var pvc corev1.PersistentVolumeClaim
	if err := r.Get(context.Background(), types.NamespacedName{Namespace: "depscan-system", Name: defaultVDBClaimName}, &pvc); err == nil {
		t.Error("should not provision a PVC when ClaimName is set")
	}
}

func TestEnsureVDBClaim_Provisions(t *testing.T) {
	r := newFakeReconciler()
	sc := "local-path"
	cfg := depscanv1alpha1.DepScanConfigSpec{
		VDBCache: &depscanv1alpha1.VDBCacheSpec{Enabled: true, Size: "7Gi", StorageClassName: sc},
	}
	name, err := r.ensureVDBClaim(context.Background(), cfg, "depscan-system")
	if err != nil {
		t.Fatal(err)
	}
	if name != defaultVDBClaimName {
		t.Errorf("expected %q, got %q", defaultVDBClaimName, name)
	}

	var pvc corev1.PersistentVolumeClaim
	if err := r.Get(context.Background(), types.NamespacedName{Namespace: "depscan-system", Name: defaultVDBClaimName}, &pvc); err != nil {
		t.Fatalf("PVC should have been provisioned: %v", err)
	}
	if pvc.Spec.AccessModes[0] != corev1.ReadWriteOnce {
		t.Errorf("accessmode = %v, want RWO", pvc.Spec.AccessModes)
	}
	want := resource.MustParse("7Gi")
	if got := pvc.Spec.Resources.Requests[corev1.ResourceStorage]; got.Cmp(want) != 0 {
		t.Errorf("size = %v, want 7Gi", got)
	}
	if pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName != sc {
		t.Errorf("storageClassName = %v, want %s", pvc.Spec.StorageClassName, sc)
	}

	// Second call must be idempotent (no error, same name).
	name2, err := r.ensureVDBClaim(context.Background(), cfg, "depscan-system")
	if err != nil || name2 != defaultVDBClaimName {
		t.Errorf("second call: name=%q err=%v", name2, err)
	}
}

func TestEnsureVDBClaim_ReadWriteMany(t *testing.T) {
	r := newFakeReconciler()
	cfg := depscanv1alpha1.DepScanConfigSpec{
		VDBCache: &depscanv1alpha1.VDBCacheSpec{Enabled: true, AccessMode: "ReadWriteMany", StorageClassName: "efs"},
	}
	if _, err := r.ensureVDBClaim(context.Background(), cfg, "depscan-system"); err != nil {
		t.Fatal(err)
	}
	var pvc corev1.PersistentVolumeClaim
	if err := r.Get(context.Background(), types.NamespacedName{Namespace: "depscan-system", Name: defaultVDBClaimName}, &pvc); err != nil {
		t.Fatal(err)
	}
	if pvc.Spec.AccessModes[0] != corev1.ReadWriteMany {
		t.Errorf("accessMode = %v, want ReadWriteMany", pvc.Spec.AccessModes)
	}
	if pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName != "efs" {
		t.Errorf("storageClassName = %v, want efs", pvc.Spec.StorageClassName)
	}
}

func TestEnsureVDBClaim_DefaultSize(t *testing.T) {
	r := newFakeReconciler()
	cfg := depscanv1alpha1.DepScanConfigSpec{
		VDBCache: &depscanv1alpha1.VDBCacheSpec{Enabled: true},
	}
	if _, err := r.ensureVDBClaim(context.Background(), cfg, "depscan-system"); err != nil {
		t.Fatal(err)
	}
	var pvc corev1.PersistentVolumeClaim
	_ = r.Get(context.Background(), types.NamespacedName{Namespace: "depscan-system", Name: defaultVDBClaimName}, &pvc)
	want := resource.MustParse("10Gi")
	if got := pvc.Spec.Resources.Requests[corev1.ResourceStorage]; got.Cmp(want) != 0 {
		t.Errorf("default size = %v, want 10Gi", got)
	}
}
