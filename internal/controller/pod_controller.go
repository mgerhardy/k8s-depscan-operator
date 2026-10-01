package controller

import (
	"context"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
	"github.com/mgerhardy/k8s-depscan-operator/internal/naming"
)

// PodReconciler watches Pods across all namespaces and ensures a DepScanReport
// exists for every container image in scope. Report naming keys on the image
// so multiple pods/workloads sharing an image collapse to one report per
// namespace, enabling per-namespace queries.
type PodReconciler struct {
	client.Client
	Config *ConfigResolver
}

// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=depscan.io,resources=depscanreports,verbs=get;list;watch;create;update;patch;delete

func (r *PodReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

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

	images := collectImages(&pod)
	pullSecrets := collectPullSecrets(&pod)
	for image, workloads := range images {
		if err := r.ensureReport(ctx, req.Namespace, image, workloads, pullSecrets); err != nil {
			l.Error(err, "ensure report", "image", image)
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

func (r *PodReconciler) ensureReport(ctx context.Context, namespace, image string, workloads []depscanv1alpha1.WorkloadRef, pullSecrets []string) error {
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
			},
		}
		if err := r.Create(ctx, &report); err != nil {
			return client.IgnoreAlreadyExists(err)
		}
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
	if changed {
		return r.Update(ctx, &report)
	}
	return nil
}

// collectImages returns the set of images in a pod with the workloads/containers
// that reference them.
func collectImages(pod *corev1.Pod) map[string][]depscanv1alpha1.WorkloadRef {
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
	for _, c := range pod.Spec.Containers {
		img := c.Image
		if !hasTagOrDigest(img) {
			if s, ok := statusByName[c.Name]; ok && s != "" {
				img = s
			}
		}
		add(c.Name, img)
	}
	for _, c := range pod.Spec.InitContainers {
		add(c.Name, c.Image)
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

func ownerWorkload(pod *corev1.Pod) (kind, name string) {
	if len(pod.OwnerReferences) > 0 {
		o := pod.OwnerReferences[0]
		return o.Kind, o.Name
	}
	return "Pod", pod.Name
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
		if ex == ns {
			return false
		}
	}
	if len(cfg.IncludeNamespaces) > 0 {
		for _, in := range cfg.IncludeNamespaces {
			if in == ns {
				return true
			}
		}
		return false
	}
	return true
}

func (r *PodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Named("pod-image-discovery").
		Complete(r)
}
