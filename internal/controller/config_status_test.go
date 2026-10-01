package controller

import (
	"context"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
)

func TestConfigStatusReportsProblemsAndVDB(t *testing.T) {
	spec := depscanv1alpha1.DepScanConfigSpec{
		IncludeNamespaces: []string{"team-["},
		DefectDojo: &depscanv1alpha1.DefectDojoSpec{
			Enabled: true, URL: "https://dd", CredentialsSecret: depscanv1alpha1.SecretRef{Name: "missing"},
		},
		VDBCache: &depscanv1alpha1.VDBCacheSpec{Enabled: true, ClaimName: "cache"},
	}
	obj := &depscanv1alpha1.DepScanConfig{ObjectMeta: metav1.ObjectMeta{Name: DefaultConfigName, Generation: 3}, Spec: spec}
	c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(obj).WithStatusSubresource(obj).Build()
	res := &ConfigResolver{Client: c, loaded: true, spec: spec}
	r := &DepScanReportReconciler{Client: c, Config: res, OperatorNamespace: "depscan-system"}

	r.MaintainVDB(context.Background())

	var got depscanv1alpha1.DepScanConfig
	if err := c.Get(context.Background(), types.NamespacedName{Name: DefaultConfigName}, &got); err != nil {
		t.Fatal(err)
	}
	valid := meta.FindStatusCondition(got.Status.Conditions, depscanv1alpha1.ConditionConfigValid)
	if valid == nil || valid.Status != metav1.ConditionFalse ||
		!strings.Contains(valid.Message, "team-[") || !strings.Contains(valid.Message, "credentialsSecret") {
		t.Errorf("ConfigValid = %+v", valid)
	}
	vdb := meta.FindStatusCondition(got.Status.Conditions, depscanv1alpha1.ConditionVDBReady)
	if vdb == nil || vdb.Status != metav1.ConditionFalse || vdb.Reason != "Priming" {
		t.Errorf("VDBReady = %+v", vdb)
	}
	if got.Status.ObservedGeneration != 3 || got.Status.VDB == nil {
		t.Errorf("status = %+v", got.Status)
	}
}
