package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
)

func TestRouteBackendsResolveGatewayAddresses(t *testing.T) {
	gw := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
		"metadata": map[string]any{"name": "public", "namespace": "infra"},
		"status":   map[string]any{"addresses": []any{map[string]any{"value": "203.0.113.7"}}},
	}}
	route := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
		"metadata": map[string]any{"name": "web", "namespace": "prod"},
		"spec": map[string]any{
			"parentRefs": []any{map[string]any{"name": "public", "namespace": "infra"}},
			"rules": []any{map[string]any{"backendRefs": []any{
				map[string]any{"name": "web"},
				map[string]any{"name": "elsewhere", "namespace": "other"},
			}}},
		},
	}}
	c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(gw, route).Build()
	r := &PodReconciler{Client: c, routeKinds: []string{"HTTPRoute"}}

	got := r.routeBackends(context.Background(), "prod")
	if len(got) != 1 || got[0].Service != "web" || len(got[0].Addresses) != 1 || got[0].Addresses[0] != "203.0.113.7" {
		t.Errorf("got %+v", got)
	}
}

// A report covers every pod running its image, so it takes the most exposed
// one instead of whichever pod reconciled last.
func TestClassifyImageTakesMostExposedPod(t *testing.T) {
	public := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "web"},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, Selector: map[string]string{"app": "web"}},
	}
	public.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "34.1.2.3"}}
	env := &exposureEnv{svcs: []corev1.Service{public}}
	pod := func(name, app string) corev1.Pod {
		return corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "prod", Labels: map[string]string{"app": app}},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "app:1"}}},
		}
	}
	internal, exposed := pod("worker", "worker"), pod("web", "web")
	workloads := collectImages(&internal, false)["app:1"]

	if got, _ := env.classifyImage(&internal, "app:1", workloads, nil, false); got != depscanv1alpha1.ExposureClusterInternal {
		t.Fatalf("alone, the worker pod is %q", got)
	}
	if got, _ := env.classifyImage(&internal, "app:1", workloads, []corev1.Pod{internal, exposed}, false); got != depscanv1alpha1.ExposureInternet {
		t.Errorf("with a public peer running the image, got %q", got)
	}
}
