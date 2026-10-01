package controller

import (
	"context"
	"path"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
	"github.com/mgerhardy/k8s-depscan-operator/internal/exposure"
	"github.com/mgerhardy/k8s-depscan-operator/internal/naming"
)

// PodReconciler watches Pods across all namespaces and ensures a DepScanReport
// exists for every container image in scope. Report naming keys on the image
// so multiple pods/workloads sharing an image collapse to one report per
// namespace, enabling per-namespace queries.
type PodReconciler struct {
	client.Client
	Config *ConfigResolver
	// MaxConcurrentReconciles is how many pods reconcile in parallel
	// (default 1).
	MaxConcurrentReconciles int

	// routeKinds are the Gateway API route kinds installed in the cluster
	// (detected at setup); empty when Gateway API is absent.
	routeKinds []string
}

// gatewayGroup is the Gateway API group; routes there can expose Services
// just like Ingresses.
const gatewayGroup = "gateway.networking.k8s.io"

// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes;grpcroutes;gateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=depscan.io,resources=depscanreports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=depscan.io,resources=depscanreports/status,verbs=get;update;patch

func (r *PodReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return requeueOnConflict(r.reconcile(ctx, req))
}

func (r *PodReconciler) reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	// Fail closed: without a loaded config the namespace scope is unknown.
	if !r.Config.Loaded() {
		return ctrl.Result{RequeueAfter: configNotLoadedRequeue}, nil
	}
	cfg := r.Config.Get()
	if !namespaceInScope(req.Namespace, cfg) {
		return ctrl.Result{}, nil
	}

	var pod corev1.Pod
	if err := r.Get(ctx, req.NamespacedName, &pod); err != nil {
		// Pod gone: reports are retained (they describe images, not pods).
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if pod.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}

	images := collectImages(&pod, cfg.ScanByDigest)
	pullSecrets := collectPullSecrets(&pod)
	env := r.exposureEnv(ctx, req.Namespace)
	var peers corev1.PodList
	if env != nil {
		if err := r.List(ctx, &peers, client.InNamespace(req.Namespace)); err != nil {
			env = nil
		}
	}
	for image, workloads := range images {
		exp, evidence := env.classifyImage(&pod, image, workloads, peers.Items, cfg.ScanByDigest)
		if err := r.ensureReport(ctx, req.Namespace, image, workloads, pullSecrets, r.nodePlatform(ctx, &pod), exp, evidence); err != nil {
			l.Error(err, "ensure report", "image", image)
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

// exposureEnv holds a namespace's Services, Ingresses and Gateway API route
// backends, the inputs of exposure classification.
type exposureEnv struct {
	svcs   []corev1.Service
	ings   []networkingv1.Ingress
	routes []exposure.RouteBackend
}

// exposureEnv lists the exposure inputs of namespace ns. On lookup error it
// returns nil, so reports are still created without exposure data.
func (r *PodReconciler) exposureEnv(ctx context.Context, ns string) *exposureEnv {
	var svcs corev1.ServiceList
	if err := r.List(ctx, &svcs, client.InNamespace(ns)); err != nil {
		return nil
	}
	var ings networkingv1.IngressList
	if err := r.List(ctx, &ings, client.InNamespace(ns)); err != nil {
		return nil
	}
	return &exposureEnv{svcs: svcs.Items, ings: ings.Items, routes: r.routeBackends(ctx, ns)}
}

// classifyImage rates image by the most exposed of the running pods in the
// namespace that use it (pod plus its peers): the report is per image, so
// rating only the pod at hand would flap between workloads sharing the image.
// A nil env yields an empty tier.
func (e *exposureEnv) classifyImage(pod *corev1.Pod, image string, workloads []depscanv1alpha1.WorkloadRef, peers []corev1.Pod, byDigest bool) (depscanv1alpha1.Exposure, string) {
	if e == nil {
		return "", ""
	}
	best, note := exposure.Classify(pod.Labels, onlyInitContainers(pod, workloads), e.svcs, e.ings, e.routes...)
	for i := range peers {
		p := &peers[i]
		if p.Name == pod.Name || p.DeletionTimestamp != nil {
			continue
		}
		ws, ok := collectImages(p, byDigest)[image]
		if !ok {
			continue
		}
		if tier, n := exposure.Classify(p.Labels, onlyInitContainers(p, ws), e.svcs, e.ings, e.routes...); exposure.MoreExposed(tier, best) {
			best, note = tier, n
		}
	}
	return best, note
}

// routeBackends returns the Services in ns referenced by Gateway API routes,
// each with the addresses of the Gateways the route attaches to.
func (r *PodReconciler) routeBackends(ctx context.Context, ns string) []exposure.RouteBackend {
	var out []exposure.RouteBackend
	for _, kind := range r.routeKinds {
		var routes unstructured.UnstructuredList
		routes.SetGroupVersionKind(schema.GroupVersionKind{Group: gatewayGroup, Version: "v1", Kind: kind + "List"})
		if err := r.List(ctx, &routes, client.InNamespace(ns)); err != nil {
			continue
		}
		for i := range routes.Items {
			route := routes.Items[i].Object
			addrs := r.gatewayAddresses(ctx, ns, route)
			rules, _, _ := unstructured.NestedSlice(route, "spec", "rules")
			for _, rule := range rules {
				refs, _, _ := unstructured.NestedSlice(asMap(rule), "backendRefs")
				for _, ref := range refs {
					m := asMap(ref)
					name, _ := m["name"].(string)
					kind, _ := m["kind"].(string)
					refNS, _ := m["namespace"].(string)
					if name == "" || (kind != "" && kind != "Service") || (refNS != "" && refNS != ns) {
						continue
					}
					out = append(out, exposure.RouteBackend{Service: name, Addresses: addrs})
				}
			}
		}
	}
	return out
}

// gatewayAddresses collects status.addresses of the Gateways a route's
// parentRefs point to.
func (r *PodReconciler) gatewayAddresses(ctx context.Context, routeNS string, route map[string]any) []string {
	var addrs []string
	parents, _, _ := unstructured.NestedSlice(route, "spec", "parentRefs")
	for _, p := range parents {
		m := asMap(p)
		if kind, _ := m["kind"].(string); kind != "" && kind != "Gateway" {
			continue
		}
		name, _ := m["name"].(string)
		ns, _ := m["namespace"].(string)
		if ns == "" {
			ns = routeNS
		}
		var gw unstructured.Unstructured
		gw.SetGroupVersionKind(schema.GroupVersionKind{Group: gatewayGroup, Version: "v1", Kind: "Gateway"})
		if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &gw); err != nil {
			continue
		}
		list, _, _ := unstructured.NestedSlice(gw.Object, "status", "addresses")
		for _, a := range list {
			if v, _ := asMap(a)["value"].(string); v != "" {
				addrs = append(addrs, v)
			}
		}
	}
	return addrs
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// onlyInitContainers reports whether this image appears solely as an init
// container in the pod (not a long-running listener).
func onlyInitContainers(pod *corev1.Pod, workloads []depscanv1alpha1.WorkloadRef) bool {
	runtimeNames := map[string]bool{}
	for _, c := range pod.Spec.Containers {
		runtimeNames[c.Name] = true
	}
	for _, w := range workloads {
		if runtimeNames[w.Container] {
			return false
		}
	}
	return true
}

func (r *PodReconciler) ensureReport(ctx context.Context, namespace, image string, workloads []depscanv1alpha1.WorkloadRef, pullSecrets []string, platform string, exp depscanv1alpha1.Exposure, evidence string) error {
	name := naming.ReportName(image)
	var report depscanv1alpha1.DepScanReport
	err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &report)
	if apierrors.IsNotFound(err) {
		report = depscanv1alpha1.DepScanReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
				Labels: map[string]string{
					depscanv1alpha1.LabelManagedBy:   depscanv1alpha1.ManagedByValue,
					depscanv1alpha1.LabelImageDigest: naming.ImageKey(image),
				},
				Annotations: map[string]string{
					depscanv1alpha1.AnnotationImage: image,
				},
			},
			Spec: depscanv1alpha1.DepScanReportSpec{
				Image:            image,
				Workloads:        workloads,
				ImagePullSecrets: pullSecrets,
				Platform:         platform,
			},
		}
		if err := r.Create(ctx, &report); err != nil {
			return client.IgnoreAlreadyExists(err)
		}
		r.updateExposure(ctx, &report, exp, evidence)
		return nil
	}
	if err != nil {
		return err
	}

	// Keep the workload list and pull secrets fresh.
	changed := mergeWorkloads(&report, workloads)
	if mergeStrings(&report.Spec.ImagePullSecrets, pullSecrets) {
		changed = true
	}
	// Record the platform once; a multi-arch image on mixed nodes keeps the
	// first one seen rather than flapping.
	if report.Spec.Platform == "" && platform != "" {
		report.Spec.Platform = platform
		changed = true
	}
	if changed {
		if err := r.Update(ctx, &report); err != nil {
			return err
		}
	}
	r.updateExposure(ctx, &report, exp, evidence)
	return nil
}

// nodePlatform returns the os/arch of the node a pod runs on ("" when not
// scheduled yet or unknown).
func (r *PodReconciler) nodePlatform(ctx context.Context, pod *corev1.Pod) string {
	if pod.Spec.NodeName == "" {
		return ""
	}
	var node corev1.Node
	if err := r.Get(ctx, types.NamespacedName{Name: pod.Spec.NodeName}, &node); err != nil {
		return ""
	}
	osName, arch := node.Labels[corev1.LabelOSStable], node.Labels[corev1.LabelArchStable]
	if osName == "" || arch == "" {
		return ""
	}
	return osName + "/" + arch
}

// updateExposure writes the exposure tier to the report status when it changed.
// Best-effort: a transient failure is retried on the next reconcile.
func (r *PodReconciler) updateExposure(ctx context.Context, report *depscanv1alpha1.DepScanReport, exp depscanv1alpha1.Exposure, evidence string) {
	if exp == "" || (report.Status.Exposure == exp && report.Status.ExposureEvidence == evidence) {
		return
	}
	// Patch only these two fields: a full status update would conflict with
	// (or, from a stale copy, clobber) the scan results the report controller
	// writes concurrently.
	base := report.DeepCopy()
	report.Status.Exposure = exp
	report.Status.ExposureEvidence = evidence
	_ = r.Status().Patch(ctx, report, client.MergeFrom(base))
}

// collectImages returns the set of images in a pod with the workloads/containers
// that reference them.
//
// With byDigest, a container whose status reports the digest it actually runs
// is scanned by that digest, so a moved tag cannot make the report describe a
// different image than the one running.
func collectImages(pod *corev1.Pod, byDigest bool) map[string][]depscanv1alpha1.WorkloadRef {
	out := map[string][]depscanv1alpha1.WorkloadRef{}
	kind, name := ownerWorkload(pod)

	add := func(containerName, image string) {
		image = normalizeImage(image)
		if image == "" {
			return
		}
		out[image] = append(out[image], depscanv1alpha1.WorkloadRef{
			Kind:      kind,
			Name:      name,
			Container: containerName,
		})
	}

	// Prefer the image reference the workload declares, since that is what the
	// cluster is known to be able to pull. Some registries (e.g. certain
	// Artifactory repos) do not serve manifests by digest, so the resolved
	// status digest is only used as a fallback when the spec reference lacks a
	// tag or digest.
	statusByName := map[string]string{}
	for _, cs := range pod.Status.ContainerStatuses {
		statusByName[cs.Name] = resolvedImage(cs.ImageID)
	}
	initStatusByName := map[string]string{}
	for _, cs := range pod.Status.InitContainerStatuses {
		initStatusByName[cs.Name] = resolvedImage(cs.ImageID)
	}
	pick := func(spec, resolved string) string {
		if resolved != "" && (byDigest || !hasTagOrDigest(spec)) {
			return resolved
		}
		return spec
	}
	for _, c := range pod.Spec.Containers {
		add(c.Name, pick(c.Image, statusByName[c.Name]))
	}
	for _, c := range pod.Spec.InitContainers {
		img := c.Image
		if byDigest {
			img = pick(c.Image, initStatusByName[c.Name])
		}
		add(c.Name, img)
	}
	return out
}

// hasTagOrDigest reports whether an image reference carries an explicit tag or
// digest (and is therefore pullable as-is).
func hasTagOrDigest(image string) bool {
	if strings.Contains(image, "@") {
		return true
	}
	// A ':' after the last '/' is a tag (ignore ':' in a registry host:port).
	lastSlash := strings.LastIndex(image, "/")
	return strings.Contains(image[lastSlash+1:], ":")
}

func resolvedImage(imageID string) string {
	// imageID looks like "docker-pullable://repo@sha256:..." or "repo@sha256:..".
	id := imageID
	if idx := strings.Index(id, "://"); idx >= 0 {
		id = id[idx+3:]
	}
	if strings.Contains(id, "@sha256:") {
		return id
	}
	return ""
}

func normalizeImage(image string) string {
	return strings.TrimSpace(image)
}

// ownerWorkload names the workload behind a pod. A ReplicaSet created by a
// Deployment is reported as that Deployment (its name minus the
// pod-template-hash suffix), so rollouts do not add a new entry each time.
func ownerWorkload(pod *corev1.Pod) (kind, name string) {
	o := metav1.GetControllerOf(pod)
	if o == nil && len(pod.OwnerReferences) > 0 {
		o = &pod.OwnerReferences[0]
	}
	if o == nil {
		return "Pod", pod.Name
	}
	if o.Kind == "ReplicaSet" {
		if h := pod.Labels["pod-template-hash"]; h != "" && strings.HasSuffix(o.Name, "-"+h) {
			return "Deployment", strings.TrimSuffix(o.Name, "-"+h)
		}
	}
	return o.Kind, o.Name
}

func mergeWorkloads(report *depscanv1alpha1.DepScanReport, incoming []depscanv1alpha1.WorkloadRef) bool {
	seen := map[string]bool{}
	for _, w := range report.Spec.Workloads {
		seen[w.Kind+"/"+w.Name+"/"+w.Container] = true
	}
	changed := false
	for _, w := range incoming {
		key := w.Kind + "/" + w.Name + "/" + w.Container
		if !seen[key] {
			report.Spec.Workloads = append(report.Spec.Workloads, w)
			seen[key] = true
			changed = true
		}
	}
	return changed
}

// collectPullSecrets returns the names of the pod's imagePullSecrets. The pod's
// ServiceAccount pull secrets are already merged into pod.Spec.ImagePullSecrets
// by the API server, so this single source is sufficient.
func collectPullSecrets(pod *corev1.Pod) []string {
	var out []string
	for _, ref := range pod.Spec.ImagePullSecrets {
		if ref.Name != "" {
			out = append(out, ref.Name)
		}
	}
	return out
}

// mergeStrings adds any missing values from incoming into *dst, returning
// whether dst changed.
func mergeStrings(dst *[]string, incoming []string) bool {
	seen := map[string]bool{}
	for _, s := range *dst {
		seen[s] = true
	}
	changed := false
	for _, s := range incoming {
		if s != "" && !seen[s] {
			*dst = append(*dst, s)
			seen[s] = true
			changed = true
		}
	}
	return changed
}

func namespaceInScope(ns string, cfg depscanv1alpha1.DepScanConfigSpec) bool {
	for _, ex := range cfg.ExcludeNamespaces {
		if nsMatch(ex, ns) {
			return false
		}
	}
	if len(cfg.IncludeNamespaces) > 0 {
		for _, in := range cfg.IncludeNamespaces {
			if nsMatch(in, ns) {
				return true
			}
		}
		return false
	}
	return true
}

// nsMatch reports whether a namespace matches an include/exclude entry. Entries
// are shell-style globs (e.g. "team-*", "*-prod", "app-?"); an entry without
// glob metacharacters is an exact match. A malformed pattern falls back to
// exact string comparison so it can never match more than intended.
func nsMatch(pattern, ns string) bool {
	if ok, err := path.Match(pattern, ns); err == nil {
		return ok
	}
	return pattern == ns
}

func (r *PodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Exposure depends on the namespace's Services and front doors, so their
	// changes re-classify the pods in that namespace.
	podsInNamespace := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		var pods corev1.PodList
		if err := r.List(ctx, &pods, client.InNamespace(obj.GetNamespace())); err != nil {
			return nil
		}
		reqs := make([]reconcile.Request, 0, len(pods.Items))
		for i := range pods.Items {
			reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&pods.Items[i])})
		}
		return reqs
	})
	// A widened namespace scope must reach pods that already run there, not
	// just new ones. Refresh first: the resolver is updated by a separate
	// handler on the same informer, in no guaranteed order.
	podsInScope := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, _ client.Object) []reconcile.Request {
		if err := r.Config.Refresh(ctx); err != nil {
			log.FromContext(ctx).Error(err, "refresh DepScanConfig")
		}
		cfg := r.Config.Get()
		var pods corev1.PodList
		if err := r.List(ctx, &pods); err != nil {
			return nil
		}
		var reqs []reconcile.Request
		for i := range pods.Items {
			if namespaceInScope(pods.Items[i].Namespace, cfg) {
				reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&pods.Items[i])})
			}
		}
		return reqs
	})
	b := ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Named("pod-image-discovery").
		Watches(&corev1.Service{}, podsInNamespace).
		Watches(&networkingv1.Ingress{}, podsInNamespace).
		Watches(&depscanv1alpha1.DepScanConfig{}, podsInScope,
			builder.WithPredicates(predicate.GenerationChangedPredicate{}))

	// Gateway API is optional: only watch route kinds whose CRDs exist.
	for _, kind := range []string{"HTTPRoute", "GRPCRoute"} {
		if _, err := mgr.GetRESTMapper().RESTMapping(schema.GroupKind{Group: gatewayGroup, Kind: kind}, "v1"); err != nil {
			continue
		}
		r.routeKinds = append(r.routeKinds, kind)
		u := &unstructured.Unstructured{}
		u.SetGroupVersionKind(schema.GroupVersionKind{Group: gatewayGroup, Version: "v1", Kind: kind})
		b = b.Watches(u, podsInNamespace)
	}
	return b.WithOptions(controller.Options{MaxConcurrentReconciles: r.MaxConcurrentReconciles}).
		Complete(r)
}
