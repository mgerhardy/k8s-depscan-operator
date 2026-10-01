package controller

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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
	c := fake.NewClientBuilder().WithScheme(reportReconcilerScheme()).WithObjects(gw, route).Build()
	r := &PodReconciler{Client: c, routeKinds: []string{"HTTPRoute"}}

	got := r.routeBackends(context.Background(), "prod")
	if len(got) != 1 || got[0].Service != "web" || len(got[0].Addresses) != 1 || got[0].Addresses[0] != "203.0.113.7" {
		t.Errorf("got %+v", got)
	}
}
