// Package exposure classifies how network-reachable a workload is, which is the
// strongest signal for whether an image's CVEs are actually exploitable.
package exposure

import (
	"net"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
)

// order ranks tiers from most to least exposed for picking the worst case.
var order = map[depscanv1alpha1.Exposure]int{
	depscanv1alpha1.ExposureInternet:        0,
	depscanv1alpha1.ExposureNetworkAdjacent: 1,
	depscanv1alpha1.ExposureClusterInternal: 2,
	depscanv1alpha1.ExposureNotAService:     3,
}

// RouteBackend is a Service referenced by a Gateway API route, with the
// addresses of the Gateways the route attaches to (empty when unknown).
type RouteBackend struct {
	Service   string
	Addresses []string
}

// Classify returns the exposure tier (and a short reason) for a pod, given the
// Services, Ingresses and Gateway API route backends in its namespace.
// isInitOnly marks a pod/container that only ran init containers for this
// image (not a listening target). When the evidence is ambiguous (an Ingress
// or Gateway without a reported address) the more exposed tier is assumed.
func Classify(podLabels map[string]string, isInitOnly bool, svcs []corev1.Service, ings []networkingv1.Ingress, routes ...RouteBackend) (depscanv1alpha1.Exposure, string) {
	if isInitOnly {
		return depscanv1alpha1.ExposureNotAService, "init container (runs to completion, not a listener)"
	}

	matched := matchingServices(podLabels, svcs)
	if len(matched) == 0 {
		return depscanv1alpha1.ExposureClusterInternal, "no matching service (internal/headless only)"
	}

	fronted := ingressFrontedServices(ings)
	for _, rb := range routes {
		tier, note := addressTier(rb.Addresses, "routed by a Gateway")
		fronted[rb.Service] = worse(fronted[rb.Service], verdict{tier, note})
	}

	best := depscanv1alpha1.ExposureNotAService
	bestNote := ""
	for i := range matched {
		tier, note := classifyService(&matched[i], fronted)
		if bestNote == "" || order[tier] < order[best] {
			best, bestNote = tier, note
		}
	}
	return best, bestNote
}

// MoreExposed reports whether tier a is more exposed than tier b (any tier
// beats an empty one).
func MoreExposed(a, b depscanv1alpha1.Exposure) bool {
	if b == "" {
		return a != ""
	}
	if a == "" {
		return false
	}
	return order[a] < order[b]
}

// verdict is a tier plus its evidence.
type verdict struct {
	tier depscanv1alpha1.Exposure
	note string
}

// worse returns the more exposed of two verdicts (a zero verdict loses).
func worse(a, b verdict) verdict {
	if a.tier == "" || order[b.tier] < order[a.tier] {
		return b
	}
	return a
}

// addressTier rates a front door (Ingress or Gateway) by its addresses: all
// private means network-adjacent, anything public (or no address reported,
// which most often means a controller that does not publish one) means
// internet.
func addressTier(addrs []string, what string) (depscanv1alpha1.Exposure, string) {
	switch {
	case len(addrs) == 0:
		return depscanv1alpha1.ExposureInternet, what + " (address unknown, assumed internet-facing)"
	case allPrivate(addrs):
		return depscanv1alpha1.ExposureNetworkAdjacent, what + " on a private address"
	default:
		return depscanv1alpha1.ExposureInternet, what + " on a public address"
	}
}

// classifyService rates a Service by its own type and by any Ingress or
// Gateway in front of it, whichever is more exposed (NodePort and LoadBalancer
// Services are common Ingress backends, e.g. GKE Ingress or ALB instance mode).
func classifyService(s *corev1.Service, fronted map[string]verdict) (depscanv1alpha1.Exposure, string) {
	own := classifyServiceType(s)
	if v, ok := fronted[s.Name]; ok && order[v.tier] < order[own.tier] {
		return v.tier, v.note
	}
	return own.tier, own.note
}

func classifyServiceType(s *corev1.Service) verdict {
	switch s.Spec.Type {
	case corev1.ServiceTypeLoadBalancer:
		var addrs []string
		for _, ing := range s.Status.LoadBalancer.Ingress {
			if a := ing.IP; a != "" {
				addrs = append(addrs, a)
			} else if ing.Hostname != "" {
				addrs = append(addrs, ing.Hostname)
			}
		}
		if len(addrs) == 0 {
			return verdict{depscanv1alpha1.ExposureNetworkAdjacent, "LoadBalancer (address pending)"}
		}
		if allPrivate(addrs) {
			return verdict{depscanv1alpha1.ExposureNetworkAdjacent, "LoadBalancer on private address"}
		}
		return verdict{depscanv1alpha1.ExposureInternet, "LoadBalancer on public address"}
	case corev1.ServiceTypeNodePort:
		return verdict{depscanv1alpha1.ExposureNetworkAdjacent, "NodePort service"}
	default: // ClusterIP / ExternalName
		return verdict{depscanv1alpha1.ExposureClusterInternal, "ClusterIP only"}
	}
}

// matchingServices returns Services whose selector matches the pod labels.
func matchingServices(podLabels map[string]string, svcs []corev1.Service) []corev1.Service {
	var out []corev1.Service
	for i := range svcs {
		sel := svcs[i].Spec.Selector
		if len(sel) == 0 {
			continue // headless/selectorless service does not front this pod by labels
		}
		if selectorMatches(sel, podLabels) {
			out = append(out, svcs[i])
		}
	}
	return out
}

func selectorMatches(selector, labels map[string]string) bool {
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// ingressFrontedServices maps each Service an Ingress routes to onto the most
// exposed verdict among the Ingresses fronting it.
func ingressFrontedServices(ings []networkingv1.Ingress) map[string]verdict {
	fronted := map[string]verdict{}
	for i := range ings {
		var addrs []string
		for _, lb := range ings[i].Status.LoadBalancer.Ingress {
			if lb.IP != "" {
				addrs = append(addrs, lb.IP)
			} else if lb.Hostname != "" {
				addrs = append(addrs, lb.Hostname)
			}
		}
		tier, note := addressTier(addrs, "behind an Ingress")
		v := verdict{tier, note}
		add := func(name string) {
			if name != "" {
				fronted[name] = worse(fronted[name], v)
			}
		}
		for _, rule := range ings[i].Spec.Rules {
			if rule.HTTP == nil {
				continue
			}
			for _, p := range rule.HTTP.Paths {
				if p.Backend.Service != nil {
					add(p.Backend.Service.Name)
				}
			}
		}
		if db := ings[i].Spec.DefaultBackend; db != nil && db.Service != nil {
			add(db.Service.Name)
		}
	}
	return fronted
}

func allPrivate(addrs []string) bool {
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			return false // a hostname may resolve publicly; treat as not-private
		}
		if !ip.IsPrivate() && !ip.IsLoopback() && !cgnat.Contains(ip) {
			return false
		}
	}
	return true
}

// cgnat is the shared address space (RFC 6598), not routable on the internet.
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}
