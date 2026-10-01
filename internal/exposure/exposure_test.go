package exposure

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
)

func svc(name string, t corev1.ServiceType, selector map[string]string, lbAddrs ...string) corev1.Service {
	s := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.ServiceSpec{Type: t, Selector: selector},
	}
	for _, a := range lbAddrs {
		s.Status.LoadBalancer.Ingress = append(s.Status.LoadBalancer.Ingress, corev1.LoadBalancerIngress{IP: a})
	}
	return s
}

func ingressFor(backendSvc string) networkingv1.Ingress {
	return networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "ing"},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{{
							Backend: networkingv1.IngressBackend{
								Service: &networkingv1.IngressServiceBackend{Name: backendSvc},
							},
						}},
					},
				},
			}},
		},
	}
}

func TestClassify(t *testing.T) {
	app := map[string]string{"app": "web"}

	cases := []struct {
		name string
		init bool
		svcs []corev1.Service
		ings []networkingv1.Ingress
		want depscanv1alpha1.Exposure
	}{
		{"init container", true, nil, nil, depscanv1alpha1.ExposureNotAService},
		{"no service", false, nil, nil, depscanv1alpha1.ExposureClusterInternal},
		{"clusterip only", false, []corev1.Service{svc("web", corev1.ServiceTypeClusterIP, app)}, nil, depscanv1alpha1.ExposureClusterInternal},
		{"public LB", false, []corev1.Service{svc("web", corev1.ServiceTypeLoadBalancer, app, "52.1.2.3")}, nil, depscanv1alpha1.ExposureInternet},
		{"private LB", false, []corev1.Service{svc("web", corev1.ServiceTypeLoadBalancer, app, "10.0.0.5")}, nil, depscanv1alpha1.ExposureNetworkAdjacent},
		{"nodeport", false, []corev1.Service{svc("web", corev1.ServiceTypeNodePort, app)}, nil, depscanv1alpha1.ExposureNetworkAdjacent},
		{"clusterip behind ingress, no address", false, []corev1.Service{svc("web", corev1.ServiceTypeClusterIP, app)}, []networkingv1.Ingress{ingressFor("web")}, depscanv1alpha1.ExposureInternet},
		{"clusterip behind private ingress", false, []corev1.Service{svc("web", corev1.ServiceTypeClusterIP, app)}, []networkingv1.Ingress{ingressAt("web", "10.1.2.3")}, depscanv1alpha1.ExposureNetworkAdjacent},
		{"clusterip behind public ingress", false, []corev1.Service{svc("web", corev1.ServiceTypeClusterIP, app)}, []networkingv1.Ingress{ingressAt("web", "34.1.2.3")}, depscanv1alpha1.ExposureInternet},
		{"CGNAT LB is private", false, []corev1.Service{svc("web", corev1.ServiceTypeLoadBalancer, app, "100.64.1.1")}, nil, depscanv1alpha1.ExposureNetworkAdjacent},
		{"LB pending addr", false, []corev1.Service{svc("web", corev1.ServiceTypeLoadBalancer, app)}, nil, depscanv1alpha1.ExposureNetworkAdjacent},
	}
	for _, c := range cases {
		got, _ := Classify(app, c.init, c.svcs, c.ings)
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestClassifyPicksMostExposed(t *testing.T) {
	app := map[string]string{"app": "web"}
	svcs := []corev1.Service{
		svc("web-internal", corev1.ServiceTypeClusterIP, app),
		svc("web-lb", corev1.ServiceTypeLoadBalancer, app, "52.1.2.3"),
	}
	got, _ := Classify(app, false, svcs, nil)
	if got != depscanv1alpha1.ExposureInternet {
		t.Errorf("should pick the most-exposed tier, got %q", got)
	}
}

func TestClassifySelectorMustMatch(t *testing.T) {
	// A service selecting a different app must not match this pod.
	svcs := []corev1.Service{svc("other", corev1.ServiceTypeLoadBalancer, map[string]string{"app": "other"}, "52.1.2.3")}
	got, _ := Classify(map[string]string{"app": "web"}, false, svcs, nil)
	if got != depscanv1alpha1.ExposureClusterInternal {
		t.Errorf("non-matching selector should not expose the pod, got %q", got)
	}
}

func ingressAt(backendSvc, addr string) networkingv1.Ingress {
	ing := ingressFor(backendSvc)
	ing.Status.LoadBalancer.Ingress = []networkingv1.IngressLoadBalancerIngress{{IP: addr}}
	return ing
}

func TestClassifyGatewayRoutes(t *testing.T) {
	app := map[string]string{"app": "web"}
	svcs := []corev1.Service{svc("web", corev1.ServiceTypeClusterIP, app)}
	if got, _ := Classify(app, false, svcs, nil, RouteBackend{Service: "web", Addresses: []string{"203.0.113.9"}}); got != depscanv1alpha1.ExposureInternet {
		t.Errorf("public gateway route: got %q", got)
	}
	if got, _ := Classify(app, false, svcs, nil, RouteBackend{Service: "web", Addresses: []string{"10.0.0.9"}}); got != depscanv1alpha1.ExposureNetworkAdjacent {
		t.Errorf("private gateway route: got %q", got)
	}
	if got, _ := Classify(app, false, svcs, nil, RouteBackend{Service: "other"}); got != depscanv1alpha1.ExposureClusterInternal {
		t.Errorf("route to another service must not expose this pod: got %q", got)
	}
}
