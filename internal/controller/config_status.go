package controller

import (
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
)

// updateConfigStatus publishes ConfigValid and VDBReady conditions plus the
// VDB cache state on the "default" DepScanConfig, so an admin can check the
// operator's health in one place. A no-op when no config object exists
// (built-in defaults) or nothing changed.
func (r *DepScanReportReconciler) updateConfigStatus(ctx context.Context, cfg depscanv1alpha1.DepScanConfigSpec, vdb vdbReady, vdbErr error) {
	var obj depscanv1alpha1.DepScanConfig
	if err := r.Get(ctx, types.NamespacedName{Name: DefaultConfigName}, &obj); err != nil {
		return
	}
	base := obj.DeepCopy()
	st := &obj.Status
	gen := obj.Generation

	if problems := r.configProblems(ctx, cfg); len(problems) > 0 {
		setCondition(st, depscanv1alpha1.ConditionConfigValid, metav1.ConditionFalse, "InvalidConfig", strings.Join(problems, "; "), gen)
	} else {
		setCondition(st, depscanv1alpha1.ConditionConfigValid, metav1.ConditionTrue, "Valid", "config applied", gen)
	}

	switch {
	case !vdbCacheEnabled(cfg):
		st.VDB = nil
		setCondition(st, depscanv1alpha1.ConditionVDBReady, metav1.ConditionTrue, "CacheDisabled",
			"vdbCache is disabled: every scan downloads the full database", gen)
	default:
		st.VDB = r.vdbStatusSnapshot()
		switch {
		case vdbErr != nil:
			setCondition(st, depscanv1alpha1.ConditionVDBReady, metav1.ConditionFalse, "Error", truncateDiagnosis(vdbErr.Error()), gen)
		case vdb.ready:
			setCondition(st, depscanv1alpha1.ConditionVDBReady, metav1.ConditionTrue, "Ready", "serving version "+vdb.version, gen)
		case st.VDB.ConsecutiveFailures > 0:
			setCondition(st, depscanv1alpha1.ConditionVDBReady, metav1.ConditionFalse, "PrimeFailed", truncateDiagnosis(vdb.reason), gen)
		default:
			setCondition(st, depscanv1alpha1.ConditionVDBReady, metav1.ConditionFalse, "Priming", truncateDiagnosis(vdb.reason), gen)
		}
	}
	st.ObservedGeneration = gen

	if equality.Semantic.DeepEqual(base.Status, obj.Status) {
		return
	}
	if err := r.Status().Patch(ctx, &obj, client.MergeFrom(base)); err != nil {
		log.FromContext(ctx).Error(err, "update DepScanConfig status")
	}
}

func setCondition(st *depscanv1alpha1.DepScanConfigStatus, typ string, status metav1.ConditionStatus, reason, msg string, gen int64) {
	meta.SetStatusCondition(&st.Conditions, metav1.Condition{
		Type: typ, Status: status, Reason: reason, Message: msg, ObservedGeneration: gen,
	})
}

func (r *DepScanReportReconciler) vdbStatusSnapshot() *depscanv1alpha1.VDBStatus {
	r.vdbMu.Lock()
	defer r.vdbMu.Unlock()
	s := &depscanv1alpha1.VDBStatus{
		Version:             r.vdbLatest,
		ConsecutiveFailures: int32(r.vdbPrimeFailures),
		LastError:           truncateDiagnosis(r.vdbLastError),
	}
	if !r.vdbLastPrimedAt.IsZero() {
		t := metav1.NewTime(r.vdbLastPrimedAt.Truncate(time.Second))
		s.PrimedAt = &t
	}
	if !r.vdbRetryAfter.IsZero() {
		t := metav1.NewTime(r.vdbRetryAfter.Truncate(time.Second))
		s.NextRetry = &t
	}
	return s
}

// configProblems lists settings the operator cannot apply as intended. Most
// values are validated at admission; this catches what the schema cannot:
// malformed namespace globs, missing DefectDojo credentials, and missing RBAC
// in a custom job namespace.
func (r *DepScanReportReconciler) configProblems(ctx context.Context, cfg depscanv1alpha1.DepScanConfigSpec) []string {
	var out []string
	for _, q := range []struct{ field, val string }{
		{"scanWorkSizeLimit", cfg.ScanWorkSizeLimit},
		{"vdbCache.size", cfg.VDBCache.Size},
	} {
		if _, err := resource.ParseQuantity(q.val); err != nil {
			out = append(out, fmt.Sprintf("%s %q is not a quantity", q.field, q.val))
		}
	}
	for _, list := range []struct {
		field    string
		patterns []string
	}{{"includeNamespaces", cfg.IncludeNamespaces}, {"excludeNamespaces", cfg.ExcludeNamespaces}} {
		for _, p := range list.patterns {
			if _, err := path.Match(p, ""); err != nil {
				out = append(out, fmt.Sprintf("%s entry %q is not a valid glob (matched literally)", list.field, p))
			}
		}
	}
	jobNS := r.jobNamespace(cfg)
	var jobs batchv1.JobList
	if err := r.reader().List(ctx, &jobs, client.InNamespace(jobNS), client.Limit(1)); apierrors.IsForbidden(err) {
		out = append(out, fmt.Sprintf("no access to Jobs in jobNamespace %q: create the depscan-operator Role and RoleBinding there (see docs/deploy.md)", jobNS))
	}
	if dd := cfg.DefectDojo; dd != nil && dd.Enabled {
		ns := dd.CredentialsSecret.Namespace
		if ns == "" {
			ns = r.OperatorNamespace
		}
		var secret corev1.Secret
		if err := r.reader().Get(ctx, types.NamespacedName{Namespace: ns, Name: dd.CredentialsSecret.Name}, &secret); err != nil {
			out = append(out, fmt.Sprintf("defectDojo.credentialsSecret %s/%s: %v", ns, dd.CredentialsSecret.Name, err))
		}
	}
	return out
}
