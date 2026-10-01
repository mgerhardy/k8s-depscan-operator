package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
	"github.com/mgerhardy/k8s-depscan-operator/internal/naming"
)

func prunerScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = depscanv1alpha1.AddToScheme(s)
	return s
}

func report(ns, image string) *depscanv1alpha1.DepScanReport {
	return &depscanv1alpha1.DepScanReport{
		ObjectMeta: metav1.ObjectMeta{Name: naming.ReportName(image), Namespace: ns},
		Spec:       depscanv1alpha1.DepScanReportSpec{Image: image},
	}
}

func podWithImage(ns, image string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p-" + naming.ImageKey(image), Namespace: ns},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: image}}},
	}
}

func TestPrunerDeletesOrphanedReports(t *testing.T) {
	live := report("prod", "nginx:1.25")
	orphan := report("prod", "redis:7")
	pod := podWithImage("prod", "nginx:1.25")

	c := fake.NewClientBuilder().WithScheme(prunerScheme()).
		WithObjects(live, orphan, pod).Build()

	p := ReportPruner{Client: c, Config: &ConfigResolver{Client: c}, OperatorNamespace: "depscan-system"}
	if err := p.prune(context.Background()); err != nil {
		t.Fatal(err)
	}

	var remaining depscanv1alpha1.DepScanReportList
	if err := c.List(context.Background(), &remaining); err != nil {
		t.Fatal(err)
	}
	if len(remaining.Items) != 1 {
		t.Fatalf("expected 1 report, got %d", len(remaining.Items))
	}
	if remaining.Items[0].Spec.Image != "nginx:1.25" {
		t.Errorf("kept wrong report: %s", remaining.Items[0].Spec.Image)
	}
}

func TestPrunerDeletesCredentialsSecret(t *testing.T) {
	orphan := report("prod", "private/app:1")
	orphan.Spec.ImagePullSecrets = []string{"regcred"}
	copied := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanCredentialsSecretName(orphan.Namespace, orphan.Name),
			Namespace: "depscan-system",
			Labels:    map[string]string{depscanv1alpha1.LabelManagedBy: depscanv1alpha1.ManagedByValue},
		},
		Type: corev1.SecretTypeDockerConfigJson,
	}
	c := fake.NewClientBuilder().WithScheme(prunerScheme()).
		WithObjects(orphan, copied).Build()

	p := ReportPruner{Client: c, Config: &ConfigResolver{Client: c}, OperatorNamespace: "depscan-system"}
	if err := p.prune(context.Background()); err != nil {
		t.Fatal(err)
	}

	var s corev1.Secret
	err := c.Get(context.Background(), types.NamespacedName{Namespace: "depscan-system", Name: copied.Name}, &s)
	if !apierrors.IsNotFound(err) {
		t.Errorf("credentials secret should have been deleted, got err=%v", err)
	}
}

func TestScanCredentialsSecretNameStableAndBounded(t *testing.T) {
	a := scanCredentialsSecretName("ns", "regcred")
	if a != scanCredentialsSecretName("ns", "regcred") {
		t.Error("name not stable")
	}
	long := scanCredentialsSecretName("a-very-long-namespace-name-repeated", "a-very-long-secret-name-repeated-many-times-over-and-over-and-over-and-over-and-over-and-over-and-over-and-over-and-over-and-over-and-over-and-over-and-over-and-over-and-over-and-over-and-over-and-over-and-over-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	if len(long) > 253 {
		t.Errorf("name exceeds 253 chars: %d", len(long))
	}
	if scanCredentialsSecretName("ns", "a") == scanCredentialsSecretName("ns", "b") {
		t.Error("different inputs collided")
	}
}
