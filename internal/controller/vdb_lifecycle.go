package controller

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
	"github.com/mgerhardy/k8s-depscan-operator/internal/metrics"
	"github.com/mgerhardy/k8s-depscan-operator/internal/scan"
)

const (
	// vdbStateConfigMap persists the current VDB version and when it was
	// primed, so an operator restart neither re-downloads the database nor
	// resets the refresh timer.
	vdbStateConfigMap = "depscan-vdb-state"
	// vdbGCInterval is how often stale cache versions are garbage-collected.
	vdbGCInterval = 10 * time.Minute
)

// vdbVersionKey is the shape of a version key the prime script publishes. It
// is used as a label value and a subPath, so anything else is rejected.
var vdbVersionKey = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// vdbReady reports whether the shared VDB cache has a usable version and, if so,
// its version key (empty version means "no pinning" when caching is disabled).
type vdbReady struct {
	ready   bool
	version string
	// reason explains, when not ready, what the cache is waiting on.
	reason string
}

func vdbCacheEnabled(cfg depscanv1alpha1.DepScanConfigSpec) bool {
	return cfg.VDBCache != nil && cfg.VDBCache.Enabled
}

// MaintainVDB advances the VDB lifecycle independently of scan demand: it
// observes finished prime Jobs, starts due refreshes, periodically
// garbage-collects stale versions, and publishes the DepScanConfig status.
// Safe to call often.
func (r *DepScanReportReconciler) MaintainVDB(ctx context.Context) {
	if !r.Config.Loaded() {
		return
	}
	cfg := r.Config.Get()
	// Keep the per-phase report gauges current (phases change outside ingest).
	r.recomputeVulnerabilityGauges(ctx)
	defer r.publishVDBMetrics()
	if !vdbCacheEnabled(cfg) {
		r.updateConfigStatus(ctx, cfg, vdbReady{ready: true}, nil)
		return
	}
	jobNS := r.jobNamespace(cfg)
	r.checkRefreshRequested(ctx, jobNS)
	vdb, err := r.ensureVDBReady(ctx, cfg, jobNS)
	r.updateConfigStatus(ctx, cfg, vdb, err)
	if err != nil {
		log.FromContext(ctx).Error(err, "maintain vdb cache")
		return
	}
	r.vdbMu.Lock()
	gcDue := time.Since(r.vdbLastGC) >= vdbGCInterval
	if gcDue {
		r.vdbLastGC = time.Now()
	}
	r.vdbMu.Unlock()
	if gcDue {
		r.gcVDBVersions(ctx, cfg, jobNS)
	}
}

// ensureVDBReady drives the shared-cache lifecycle: it provisions the cache
// PVC, runs/refreshes a prime Job that downloads the VDB into a per-version
// directory, and reports the current version once ready. Scans are gated on
// ready=true. When caching is disabled it returns ready with an empty version
// so scans fall back to a per-Job emptyDir.
func (r *DepScanReportReconciler) ensureVDBReady(ctx context.Context, cfg depscanv1alpha1.DepScanConfigSpec, jobNS string) (vdbReady, error) {
	if !vdbCacheEnabled(cfg) {
		return vdbReady{ready: true, version: ""}, nil
	}

	// Serialize the lifecycle: it is driven both by scan reconciles and by
	// the periodic maintainer.
	r.vdbMu.Lock()
	defer r.vdbMu.Unlock()

	claim, err := r.ensureVDBClaim(ctx, cfg, jobNS)
	if err != nil {
		return vdbReady{}, err
	}
	if err := r.loadVDBState(ctx, jobNS); err != nil {
		return vdbReady{}, err
	}

	// Serve the cached version unless a refresh is due.
	cur := r.vdbLatest
	refresh := cfg.VDBCache.RefreshInterval.Duration
	if refresh <= 0 {
		refresh = 24 * time.Hour
	}
	dueForRefresh := cur != "" && time.Since(r.vdbLastPrimedAt) > refresh

	var job batchv1.Job
	err = r.Get(ctx, types.NamespacedName{Namespace: jobNS, Name: scan.VDBPrimeJobName}, &job)
	switch {
	case apierrors.IsNotFound(err):
		// No prime Job: create one (first prime, or a due refresh after the old
		// Job's TTL reaped it). If we already have a version cached, keep
		// serving it while the refresh runs.
		if cur == "" || dueForRefresh {
			if time.Now().Before(r.vdbRetryAfter) {
				// A recent prime failed; back off instead of hammering the
				// (multi-GB) download source.
				return vdbReady{ready: cur != "", version: cur, reason: fmt.Sprintf(
					"prime failed %d time(s), next attempt at %s: %s",
					r.vdbPrimeFailures, r.vdbRetryAfter.UTC().Format(time.RFC3339), r.vdbLastError)}, nil
			}
			// A refresh must fetch a new version, so it bypasses the reuse of
			// the version named by latest.meta.
			force := dueForRefresh && !r.vdbSkipForce
			if err := r.createPrimeJob(ctx, cfg, jobNS, claim, force); err != nil {
				return vdbReady{}, err
			}
			r.vdbSkipForce = false
		}
		return vdbReady{ready: cur != "", version: cur, reason: "prime Job started"}, nil
	case err != nil:
		return vdbReady{}, err
	}

	complete, failed := jobFinished(&job)
	switch {
	case complete:
		primed := time.Now()
		if job.Status.CompletionTime != nil {
			primed = job.Status.CompletionTime.Time
		}
		if primed.Before(r.vdbRefreshRequestedAt) {
			// Finished before a forced refresh was requested: replace it.
			_ = r.deleteJob(ctx, &job)
			return vdbReady{ready: cur != "", version: cur, reason: "refresh requested"}, nil
		}
		version := r.primedVersion(ctx, jobNS, &job)
		if version == "" {
			// The result is unreadable (e.g. its pod is gone). Re-prime; the
			// pointer is already published, so reuse it rather than download.
			r.vdbSkipForce = true
			_ = r.deleteJob(ctx, &job)
			return vdbReady{ready: cur != "", version: cur}, nil
		}
		// Record the prime time even when the version is unchanged (the
		// upstream DB was not republished yet); otherwise the refresh would
		// stay due and re-download in a tight loop. CompletionTime keeps this
		// idempotent across reconciles that observe the same Job.
		changed := version != r.vdbLatest
		r.vdbLatest = version
		if primed.After(r.vdbLastPrimedAt) {
			r.vdbLastPrimedAt = primed
			changed = true
		}
		r.vdbPrimeFailures = 0
		r.vdbRetryAfter = time.Time{}
		r.vdbLastError = ""
		r.vdbRefreshRequestedAt = time.Time{}
		if changed {
			if err := r.saveVDBState(ctx, jobNS); err != nil {
				log.FromContext(ctx).Error(err, "persist vdb state")
			}
		}
		// If a refresh is due, delete the finished Job so the next pass
		// starts a fresh prime.
		if time.Since(r.vdbLastPrimedAt) > refresh {
			_ = r.deleteJob(ctx, &job)
		}
		return vdbReady{ready: true, version: version}, nil
	case failed:
		// The Job exhausted its own retries. Back off exponentially: delete the Job so a fresh prime is
		// created once the backoff has elapsed.
		r.vdbPrimeFailures++
		metrics.VDBPrimeFailures.Inc()
		r.vdbRetryAfter = time.Now().Add(primeBackoff(r.vdbPrimeFailures))
		r.vdbLastError = r.diagnoseJob(ctx, &job)
		if r.vdbLastError == "" {
			r.vdbLastError = "prime Job failed"
		}
		log.FromContext(ctx).Info("vdb prime failed", "failures", r.vdbPrimeFailures,
			"retryAt", r.vdbRetryAfter, "reason", r.vdbLastError)
		_ = r.deleteJob(ctx, &job)
		return vdbReady{ready: cur != "", version: cur, reason: "prime failed: " + r.vdbLastError}, nil
	default:
		// Prime in progress: ready only if we already have a usable version.
		reason := "prime running"
		if job.Status.StartTime != nil {
			reason += " since " + job.Status.StartTime.UTC().Format(time.RFC3339)
		}
		if d := r.diagnoseJob(ctx, &job); d != "" {
			reason += "; not progressing: " + d
		}
		return vdbReady{ready: cur != "", version: cur, reason: reason}, nil
	}
}

// publishVDBMetrics exports the current VDB version and its age.
func (r *DepScanReportReconciler) publishVDBMetrics() {
	r.vdbMu.Lock()
	version, primed := r.vdbLatest, r.vdbLastPrimedAt
	r.vdbMu.Unlock()
	if primed.IsZero() {
		metrics.SetVDB(version, 0)
		return
	}
	metrics.SetVDB(version, time.Since(primed).Seconds())
}

// checkRefreshRequested treats a deleted state ConfigMap as a request to
// refresh the VDB now (the documented way to force a fresh download): the
// current version keeps serving while a forced prime runs, and the prime
// recreates the ConfigMap.
func (r *DepScanReportReconciler) checkRefreshRequested(ctx context.Context, jobNS string) {
	r.vdbMu.Lock()
	defer r.vdbMu.Unlock()
	if r.vdbStateNS != jobNS || r.vdbLatest == "" || r.vdbLastPrimedAt.IsZero() {
		return
	}
	var cm corev1.ConfigMap
	err := r.reader().Get(ctx, types.NamespacedName{Namespace: jobNS, Name: vdbStateConfigMap}, &cm)
	if !apierrors.IsNotFound(err) {
		return
	}
	log.FromContext(ctx).Info("vdb state ConfigMap deleted; forcing a VDB refresh", "version", r.vdbLatest)
	r.vdbLastPrimedAt = time.Time{} // due now
	r.vdbRefreshRequestedAt = time.Now()
	r.vdbRetryAfter = time.Time{}
	r.vdbSkipForce = false
}

// primeBackoff is the wait before retrying after the n-th consecutive failed
// prime: 1m, 2m, 4m, ... capped at 1h.
func primeBackoff(failures int) time.Duration {
	d := time.Minute
	for i := 1; i < failures && d < time.Hour; i++ {
		d *= 2
	}
	if d > time.Hour {
		d = time.Hour
	}
	return d
}

// reader returns the uncached API reader when configured (production), or the
// regular client (tests).
func (r *DepScanReportReconciler) reader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

// loadVDBState reads the persisted VDB state for jobNS once (and again if the
// job namespace changes). Caller holds vdbMu.
func (r *DepScanReportReconciler) loadVDBState(ctx context.Context, jobNS string) error {
	if r.vdbStateNS == jobNS {
		return nil
	}
	var cm corev1.ConfigMap
	err := r.reader().Get(ctx, types.NamespacedName{Namespace: jobNS, Name: vdbStateConfigMap}, &cm)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	r.vdbLatest, r.vdbLastPrimedAt = "", time.Time{}
	r.vdbPrimeFailures, r.vdbRetryAfter = 0, time.Time{}
	r.vdbRefreshRequestedAt = time.Time{}
	if err == nil {
		if v := cm.Data["version"]; vdbVersionKey.MatchString(v) {
			r.vdbLatest = v
			if t, perr := time.Parse(time.RFC3339, cm.Data["primedAt"]); perr == nil {
				r.vdbLastPrimedAt = t
			}
		}
	}
	r.vdbStateNS = jobNS
	return nil
}

// saveVDBState persists the current version and prime time. Caller holds vdbMu.
func (r *DepScanReportReconciler) saveVDBState(ctx context.Context, jobNS string) error {
	data := map[string]string{
		"version":  r.vdbLatest,
		"primedAt": r.vdbLastPrimedAt.UTC().Format(time.RFC3339),
	}
	cm := corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      vdbStateConfigMap,
			Namespace: jobNS,
			Labels:    map[string]string{depscanv1alpha1.LabelManagedBy: depscanv1alpha1.ManagedByValue},
		},
		Data: data,
	}
	err := r.Create(ctx, &cm)
	if !apierrors.IsAlreadyExists(err) {
		return err
	}
	var cur corev1.ConfigMap
	if err := r.reader().Get(ctx, types.NamespacedName{Namespace: jobNS, Name: vdbStateConfigMap}, &cur); err != nil {
		return err
	}
	cur.Data = data
	return r.Update(ctx, &cur)
}

// vdbScope returns the configured VDB scope, or empty when caching is unset.
func vdbScope(cfg depscanv1alpha1.DepScanConfigSpec) string {
	if cfg.VDBCache == nil {
		return ""
	}
	return cfg.VDBCache.Scope
}

func (r *DepScanReportReconciler) createPrimeJob(ctx context.Context, cfg depscanv1alpha1.DepScanConfigSpec, jobNS, claim string, force bool) error {
	job := scan.BuildPrimeJob(scan.PrimeJobConfig{
		ScannerImage: cfg.ScannerImage,
		Namespace:    jobNS,
		VDBClaim:     claim,
		TTLSeconds:   cfg.JobTTLSeconds,
		Resources:    cfg.Resources,
		DownloadURL:  cfg.VDBCache.DownloadURL,
		Scope:        cfg.VDBCache.Scope,
		Force:        force,
		Timeout:      primeTimeout(cfg),
	})
	if err := r.Create(ctx, job); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

// primeTimeout is the configured prime deadline, defaulting to 4h.
func primeTimeout(cfg depscanv1alpha1.DepScanConfigSpec) time.Duration {
	if d := cfg.VDBCache.PrimeTimeout.Duration; d > 0 {
		return d
	}
	return 4 * time.Hour
}

// deleteJob deletes an operator-owned Job and its pods, ignoring NotFound.
func (r *DepScanReportReconciler) deleteJob(ctx context.Context, job *batchv1.Job) error {
	policy := metav1.DeletePropagationBackground
	return client.IgnoreNotFound(r.Delete(ctx, job, &client.DeleteOptions{PropagationPolicy: &policy}))
}

// primedVersion reads the published version key from the termination message
// of the prime Job's newest successful pod. Returns "" when unavailable or
// malformed.
func (r *DepScanReportReconciler) primedVersion(ctx context.Context, ns string, job *batchv1.Job) string {
	var pods corev1.PodList
	// Uncached: the Job's success can reach the cache before its pod's
	// terminated status does.
	if err := r.reader().List(ctx, &pods, client.InNamespace(ns), client.MatchingLabels{"job-name": job.Name}); err != nil {
		return ""
	}
	var newest *corev1.Pod
	version := ""
	for i := range pods.Items {
		p := &pods.Items[i]
		for _, cs := range p.Status.ContainerStatuses {
			t := cs.State.Terminated
			if cs.Name != scan.PrimeContainerName || t == nil || t.ExitCode != 0 {
				continue
			}
			v := strings.TrimSpace(t.Message)
			if !vdbVersionKey.MatchString(v) {
				continue
			}
			if newest == nil || p.CreationTimestamp.After(newest.CreationTimestamp.Time) {
				newest, version = p, v
			}
		}
	}
	return version
}

// gcVDBVersions deletes stale per-version directories from the cache. A version
// is removed only when it is NOT the current one AND no active scan Job still
// consumes it. It is a no-op when the current version is unknown or a prime is
// in flight (its fresh version may not be recorded yet). The deletion runs in a
// short Job because the operator cannot write the PVC itself.
func (r *DepScanReportReconciler) gcVDBVersions(ctx context.Context, cfg depscanv1alpha1.DepScanConfigSpec, jobNS string) {
	if !vdbCacheEnabled(cfg) {
		return
	}
	r.vdbMu.Lock()
	defer r.vdbMu.Unlock()
	current := r.vdbLatest
	if current == "" || r.vdbStateNS != jobNS {
		return // never GC when the current version is unknown
	}
	// A prime Job exists? Its version may be published but not yet observed;
	// skip so it cannot be deleted out from under the pointer.
	var prime batchv1.Job
	if err := r.Get(ctx, types.NamespacedName{Namespace: jobNS, Name: scan.VDBPrimeJobName}, &prime); err == nil {
		return
	}
	// A GC Job already running? Skip.
	var existing batchv1.Job
	if err := r.Get(ctx, types.NamespacedName{Namespace: jobNS, Name: scan.VDBGCJobName}, &existing); err == nil {
		if complete, failed := jobFinished(&existing); !complete && !failed {
			return
		}
		_ = r.deleteJob(ctx, &existing) // reap a finished GC Job
		return
	}

	claim, err := r.ensureVDBClaim(ctx, cfg, jobNS)
	if err != nil {
		return
	}
	inUse, err := r.versionsInUse(ctx, jobNS)
	if err != nil {
		log.FromContext(ctx).Error(err, "list scan jobs for vdb gc")
		return // never GC without knowing which versions scans use
	}
	keep := []string{current}
	for v := range inUse {
		keep = append(keep, v)
	}
	job := scan.BuildVDBGCJob(scan.VDBGCJobConfig{
		ScannerImage: cfg.ScannerImage,
		Namespace:    jobNS,
		VDBClaim:     claim,
		TTLSeconds:   cfg.JobTTLSeconds,
		KeepVersions: keep,
	})
	if err := r.Create(ctx, job); err != nil && !apierrors.IsAlreadyExists(err) {
		log.FromContext(ctx).Error(err, "create vdb gc job")
	}
}

// versionsInUse returns the set of VDB versions referenced by active (not
// finished, possibly retrying) scan Jobs, read uncached so a just-created scan
// is not missed.
func (r *DepScanReportReconciler) versionsInUse(ctx context.Context, jobNS string) (map[string]bool, error) {
	inUse := map[string]bool{}
	var jobs batchv1.JobList
	if err := r.reader().List(ctx, &jobs, client.InNamespace(jobNS),
		client.MatchingLabels{depscanv1alpha1.LabelManagedBy: depscanv1alpha1.ManagedByValue}); err != nil {
		return nil, err
	}
	for i := range jobs.Items {
		j := &jobs.Items[i]
		if complete, failed := jobFinished(j); !complete && !failed {
			if v := j.Labels[depscanv1alpha1.LabelVDBVersion]; v != "" {
				inUse[v] = true
			}
		}
	}
	return inUse, nil
}
