package controller

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
)

// ReportPruner periodically removes DepScanReports whose image is no longer
// running on any in-scope pod, and the pull-secret copies they own. Reports are
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
	cfg := p.Config.Get()

	live, err := p.liveImages(ctx, cfg)
	if err != nil {
		return err
	}

	var reports depscanv1alpha1.DepScanReportList
	if err := p.Client.List(ctx, &reports); err != nil {
		return err
	}

	jobNS := cfg.JobNamespace
	if jobNS == "" {
		jobNS = p.OperatorNamespace
	}

	for i := range reports.Items {
		r := &reports.Items[i]
		if live[r.Namespace+"\x00"+r.Spec.Image] {
			continue
		}
		p.deleteCredentialsSecret(ctx, r, jobNS)
		if err := p.Client.Delete(ctx, r); err != nil {
			return client.IgnoreNotFound(err)
		}
	}
	return nil
}

func (p ReportPruner) liveImages(ctx context.Context, cfg depscanv1alpha1.DepScanConfigSpec) (map[string]bool, error) {
	var pods corev1.PodList
	if err := p.Client.List(ctx, &pods); err != nil {
		return nil, err
	}
	live := map[string]bool{}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !namespaceInScope(pod.Namespace, cfg) {
			continue
		}
		for image := range collectImages(pod) {
			live[pod.Namespace+"\x00"+image] = true
		}
	}
	return live, nil
}

func (p ReportPruner) deleteCredentialsSecret(ctx context.Context, report *depscanv1alpha1.DepScanReport, jobNS string) {
	name := scanCredentialsSecretName(report.Namespace, report.Name)
	secret := &corev1.Secret{}
	if err := p.Client.Get(ctx, client.ObjectKey{Namespace: jobNS, Name: name}, secret); err != nil {
		return
	}
	if secret.Labels[depscanv1alpha1.LabelManagedBy] == depscanv1alpha1.ManagedByValue {
		_ = p.Client.Delete(ctx, secret)
	}
}
