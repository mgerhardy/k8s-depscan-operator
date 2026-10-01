package controller

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
)

// ReportPruner periodically removes DepScanReports whose image is no longer
// running on any in-scope pod, together with their scan Jobs and pull-secret
// copies. Reports are
// keyed per image rather than per pod, so without this they would accumulate as
// workloads come and go.
type ReportPruner struct {
	Client            client.Client
	Config            *ConfigResolver
	OperatorNamespace string
	Interval          time.Duration
}

func (p ReportPruner) Start(ctx context.Context) error {
	interval := p.Interval
	if interval == 0 {
		interval = time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := p.prune(ctx); err != nil {
				log.FromContext(ctx).Error(err, "report prune failed")
			}
		}
	}
}

func (p ReportPruner) prune(ctx context.Context) error {
	if !p.Config.Loaded() {
		return nil
	}
	cfg := p.Config.Get()

	// Reports first: a report is only created for a pod already in the pod
	// cache, so listing pods afterwards cannot miss the pod of a report that
	// appeared in between.
	var reports depscanv1alpha1.DepScanReportList
	if err := p.Client.List(ctx, &reports); err != nil {
		return err
	}

	live, err := p.liveImages(ctx, cfg)
	if err != nil {
		return err
	}

	jobNS := JobNamespace(cfg, p.OperatorNamespace)

	deleted := false
	var failed []error
	for i := range reports.Items {
		r := &reports.Items[i]
		if usage, ok := live[r.Namespace+"\x00"+r.Spec.Image]; ok {
			p.syncUsage(ctx, r, usage)
			continue
		}
		if err := deleteReportScanResources(ctx, p.Client, p.Client, jobNS, r.Namespace, r.Name); err != nil {
			failed = append(failed, err)
			continue
		}
		if err := client.IgnoreNotFound(p.Client.Delete(ctx, r)); err != nil {
			// Keep pruning the rest; report the failure at the end.
			failed = append(failed, err)
			continue
		}
		deleted = true
	}
	if deleted {
		recomputeReportGauges(ctx, p.Client)
	}
	return errors.Join(failed...)
}

// imageUsage is who currently runs an image in a namespace.
type imageUsage struct {
	workloads   []depscanv1alpha1.WorkloadRef
	pullSecrets []string
}

// liveImages maps "namespace\x00image" to the workloads and pull secrets of
// the in-scope pods currently running it.
func (p ReportPruner) liveImages(ctx context.Context, cfg depscanv1alpha1.DepScanConfigSpec) (map[string]*imageUsage, error) {
	var pods corev1.PodList
	if err := p.Client.List(ctx, &pods); err != nil {
		return nil, err
	}
	live := map[string]*imageUsage{}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !namespaceInScope(pod.Namespace, cfg) {
			continue
		}
		secrets := collectPullSecrets(pod)
		for image, workloads := range collectImages(pod, cfg.ScanByDigest) {
			key := pod.Namespace + "\x00" + image
			u := live[key]
			if u == nil {
				u = &imageUsage{}
				live[key] = u
			}
			for _, w := range workloads {
				u.workloads = appendUniqueWorkload(u.workloads, w)
			}
			mergeStrings(&u.pullSecrets, secrets)
		}
	}
	for _, u := range live {
		sortWorkloads(u.workloads)
		sort.Strings(u.pullSecrets)
	}
	return live, nil
}

// syncUsage replaces a report's workloads and pull secrets with the ones
// currently running the image. The pod controller only ever adds entries, so
// without this they would grow with every rollout (each new ReplicaSet) and
// keep secrets that are no longer referenced.
func (p ReportPruner) syncUsage(ctx context.Context, r *depscanv1alpha1.DepScanReport, u *imageUsage) {
	cur := append([]depscanv1alpha1.WorkloadRef(nil), r.Spec.Workloads...)
	sortWorkloads(cur)
	secrets := append([]string(nil), r.Spec.ImagePullSecrets...)
	sort.Strings(secrets)
	if reflect.DeepEqual(cur, u.workloads) && slices.Equal(secrets, u.pullSecrets) {
		return
	}
	r.Spec.Workloads = u.workloads
	r.Spec.ImagePullSecrets = u.pullSecrets
	if err := p.Client.Update(ctx, r); err != nil && !apierrors.IsConflict(err) && !apierrors.IsNotFound(err) {
		log.FromContext(ctx).Error(err, "sync report workloads", "namespace", r.Namespace, "name", r.Name)
	}
}

func appendUniqueWorkload(ws []depscanv1alpha1.WorkloadRef, w depscanv1alpha1.WorkloadRef) []depscanv1alpha1.WorkloadRef {
	for _, x := range ws {
		if x == w {
			return ws
		}
	}
	return append(ws, w)
}

func sortWorkloads(ws []depscanv1alpha1.WorkloadRef) {
	sort.Slice(ws, func(i, j int) bool {
		a, b := ws[i], ws[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Container < b.Container
	})
}
