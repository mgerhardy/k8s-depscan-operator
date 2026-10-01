package controller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
	"github.com/mgerhardy/k8s-depscan-operator/internal/defectdojo"
	"github.com/mgerhardy/k8s-depscan-operator/internal/dockercfg"
	"github.com/mgerhardy/k8s-depscan-operator/internal/metrics"
	"github.com/mgerhardy/k8s-depscan-operator/internal/naming"
	"github.com/mgerhardy/k8s-depscan-operator/internal/scan"
)

const (
	// jobPollFallback re-checks a running scan in case a Job event was missed.
	jobPollFallback = 2 * time.Minute
	// maxScanLogBytes bounds how much scan-pod log output is read into memory.
	maxScanLogBytes = 16 << 20 // 16 MiB
	// maxStoredVulnerabilities and maxStoredVulnerabilityBytes cap the
	// findings persisted in a report's status (by count and by serialized
	// size) so a pathological image cannot push the object past etcd's
	// ~1.5 MiB request limit, which would leave the report stuck.
	maxStoredVulnerabilities    = 2000
	maxStoredVulnerabilityBytes = 768 << 10 // 768 KiB
)

// DepScanReportReconciler drives the scan lifecycle for a single report:
// create a Job, wait for completion, ingest the dep-scan output from the pod
// logs, update status, optionally export to DefectDojo, and rescan on an
// interval.
type DepScanReportReconciler struct {
	client.Client
	// APIReader reads directly from the API server, bypassing the cache. Used
	// for objects the operator must not cache cluster-wide. Optional (falls
	// back to Client).
	APIReader client.Reader
	Clientset kubernetes.Interface
	// Recorder emits Kubernetes Events on reports (optional).
	Recorder          events.EventRecorder
	Config            *ConfigResolver
	OperatorNamespace string
	// MaxConcurrentReconciles is how many reports reconcile in parallel
	// (default 1). Slow steps (log streaming, DefectDojo upload) then no longer
	// stall every other report.
	MaxConcurrentReconciles int

	// scanSlotMu makes the capacity check and Job creation atomic across
	// concurrent reconciles.
	scanSlotMu sync.Mutex

	// vdbMu guards the VDB lifecycle state below and serializes the lifecycle
	// operations that act on it.
	vdbMu           sync.Mutex
	vdbStateNS      string    // job namespace the state was loaded for
	vdbLatest       string    // current VDB version (persisted in vdbStateConfigMap)
	vdbLastPrimedAt time.Time // when the current version was last primed
	// vdbPrimeFailures counts consecutive failed prime Jobs; vdbRetryAfter
	// holds off the next prime until the backoff has elapsed.
	vdbPrimeFailures int
	vdbRetryAfter    time.Time
	// vdbSkipForce makes the next prime reuse the published pointer even if a
	// refresh is due (used when a finished prime's result was unreadable).
	vdbSkipForce bool
	vdbLastGC    time.Time
	// vdbLastError explains the most recent failed prime.
	vdbLastError string
}

// Cluster-wide: discovery reads, reports, and pull secrets of the workloads
// being scanned (read uncached, by name only; never listed or watched).
// +kubebuilder:rbac:groups=depscan.io,resources=depscanreports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=depscan.io,resources=depscanreports/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=depscan.io,resources=depscanconfigs,verbs=get;list;watch
// +kubebuilder:rbac:groups=depscan.io,resources=depscanconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch
//
// Job namespace only: everything the operator creates or deletes.
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;delete,namespace=depscan-system
// +kubebuilder:rbac:groups="",resources=pods/log,verbs=get,namespace=depscan-system
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;create;update;delete,namespace=depscan-system
// +kubebuilder:rbac:groups="",resources=persistentvolumeclaims,verbs=get;list;watch;create,namespace=depscan-system
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;create;update,namespace=depscan-system
// +kubebuilder:rbac:groups="",resources=events,verbs=list,namespace=depscan-system

func (r *DepScanReportReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return requeueOnConflict(r.reconcile(ctx, req))
}

func (r *DepScanReportReconciler) reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	// Fail closed: without a loaded config the namespace scope is unknown.
	if !r.Config.Loaded() {
		return ctrl.Result{RequeueAfter: configNotLoadedRequeue}, nil
	}

	var report depscanv1alpha1.DepScanReport
	if err := r.Get(ctx, req.NamespacedName, &report); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	cfg := r.Config.Get()
	jobNS := r.jobNamespace(cfg)

	// Scope changes apply to existing reports too: a report whose namespace is
	// no longer in scope is deleted along with its scan Job.
	if !namespaceInScope(report.Namespace, cfg) {
		if report.Status.ScanJob != "" {
			_ = r.deleteScanJob(ctx, jobNS, report.Status.ScanJob)
		}
		deleteScanCredentials(ctx, r.Client, r.reader(), jobNS, &report)
		l.Info("report namespace out of scope, deleting", "namespace", report.Namespace, "name", report.Name)
		if err := client.IgnoreNotFound(r.Delete(ctx, &report)); err != nil {
			return ctrl.Result{}, err
		}
		r.recomputeVulnerabilityGauges(ctx)
		return ctrl.Result{}, nil
	}

	if _, ok := report.Annotations[AnnotationRescan]; ok {
		return r.handleRescanRequest(ctx, &report)
	}

	switch report.Status.Phase {
	case "", depscanv1alpha1.PhasePending:
		return r.startScan(ctx, &report, cfg, jobNS)
	case depscanv1alpha1.PhaseScanning:
		return r.checkScan(ctx, &report, cfg, jobNS)
	case depscanv1alpha1.PhaseCompleted, depscanv1alpha1.PhaseFailed:
		return r.maybeRescan(ctx, &report, cfg, jobNS)
	default:
		l.Info("unknown phase, resetting", "phase", report.Status.Phase)
		return r.startScan(ctx, &report, cfg, jobNS)
	}
}

func (r *DepScanReportReconciler) startScan(ctx context.Context, report *depscanv1alpha1.DepScanReport, cfg depscanv1alpha1.DepScanConfigSpec, jobNS string) (ctrl.Result, error) {
	// Gate scans until the shared VDB cache has a usable version. This also
	// provisions the cache PVC and runs the prime Job.
	vdb, err := r.ensureVDBReady(ctx, cfg, jobNS)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("ensure vdb ready: %w", err)
	}
	if !vdb.ready {
		msg := "waiting for vulnerability database"
		if vdb.reason != "" {
			msg += ": " + vdb.reason
		}
		r.setMessage(ctx, report, msg)
		return ctrl.Result{RequeueAfter: 20 * time.Second}, nil
	}

	vdbClaimName := ""
	if cfg.VDBCache != nil && cfg.VDBCache.Enabled {
		if vdbClaimName, err = r.ensureVDBClaim(ctx, cfg, jobNS); err != nil {
			return ctrl.Result{}, fmt.Errorf("ensure vdb cache: %w", err)
		}
	}

	// Build the registry credentials for this image (resolving wildcard auth to
	// the image's host) and store them in a job-namespace Secret for crane.
	dockerCfgSecret, err := r.ensureDockerConfigSecret(ctx, report, jobNS)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("prepare registry credentials: %w", err)
	}

	var workLimit *resource.Quantity
	if q, qerr := resource.ParseQuantity(cfg.ScanWorkSizeLimit); qerr == nil {
		workLimit = &q
	} else {
		return ctrl.Result{}, fmt.Errorf("parse scanWorkSizeLimit %q: %w", cfg.ScanWorkSizeLimit, qerr)
	}
	// Without a cache each scan downloads the VDB into its own emptyDir;
	// bound it like the cache PVC would be, so a scan cannot fill the node.
	var vdbLimit *resource.Quantity
	if vdbClaimName == "" {
		if q, qerr := resource.ParseQuantity(cfg.VDBCache.Size); qerr == nil {
			vdbLimit = &q
		}
	}
	nonce, err := randomHex(16)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("generate marker nonce: %w", err)
	}
	job := scan.BuildJob(scan.JobConfig{
		Image:              report.Spec.Image,
		ScannerImage:       cfg.ScannerImage,
		CraneImage:         cfg.CraneImage,
		Profile:            cfg.ScanProfile,
		Namespace:          jobNS,
		TTLSeconds:         cfg.JobTTLSeconds,
		VDBClaim:           vdbClaimName,
		VDBVersion:         vdb.version,
		Scope:              vdbScope(cfg),
		Resources:          cfg.Resources,
		DockerConfigSecret: dockerCfgSecret,
		MarkerNonce:        nonce,
		Platform:           scanPlatform(cfg, report),
		Timeout:            cfg.ScanTimeout.Duration,
		WorkSizeLimit:      workLimit,
		VDBSizeLimit:       vdbLimit,
		OwnerLabels: map[string]string{
			scan.LabelReportNamespace: report.Namespace,
			scan.LabelReportName:      report.Name,
		},
	})

	existing := &batchv1.Job{}
	err = r.Get(ctx, types.NamespacedName{Namespace: jobNS, Name: job.Name}, existing)
	if apierrors.IsNotFound(err) {
		created, active, err := r.createWithinCapacity(ctx, job, jobNS, cfg.MaxConcurrentScans)
		if err != nil {
			return ctrl.Result{}, err
		}
		if !created {
			// Stay Pending and retry; another scan will free a slot.
			r.setMessage(ctx, report, fmt.Sprintf("queued: %d/%d scan slots in use (maxConcurrentScans)", active, cfg.MaxConcurrentScans))
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
	} else if err != nil {
		return ctrl.Result{}, err
	} else if _, failed := jobFinished(existing); failed {
		// A retry after a failure: the previous Job (kept so its logs could be
		// inspected) is replaced by a fresh one.
		if err := r.deleteJob(ctx, existing); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	report.Status.Phase = depscanv1alpha1.PhaseScanning
	report.Status.ScanJob = job.Name
	report.Status.Scanner = cfg.ScannerImage
	report.Status.Message = "scan job started"
	now := metav1.Now()
	report.Status.UpdateTimestamp = &now
	if err := r.Status().Update(ctx, report); err != nil {
		return ctrl.Result{}, err
	}
	r.event(report, corev1.EventTypeNormal, "ScanStarted", "Scan", "scan Job %s/%s started for %s", jobNS, job.Name, report.Spec.Image)
	// Job events drive progress; this is only a safety net.
	return ctrl.Result{RequeueAfter: jobPollFallback}, nil
}

func (r *DepScanReportReconciler) checkScan(ctx context.Context, report *depscanv1alpha1.DepScanReport, cfg depscanv1alpha1.DepScanConfigSpec, jobNS string) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	var job batchv1.Job
	err := r.Get(ctx, types.NamespacedName{Namespace: jobNS, Name: report.Status.ScanJob}, &job)
	if apierrors.IsNotFound(err) {
		// Job TTL may have reaped it before we observed completion; restart.
		report.Status.Phase = depscanv1alpha1.PhasePending
		if err := r.Status().Update(ctx, report); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}
	if err != nil {
		return ctrl.Result{}, err
	}

	complete, failed := jobFinished(&job)
	if complete || failed {
		// Registry credentials are only needed for the pull; do not keep
		// them in the job namespace between scans.
		deleteScanCredentials(ctx, r.Client, r.reader(), jobNS, report)
	}
	switch {
	case complete:
		return r.ingest(ctx, report, &job, cfg, jobNS)
	case failed:
		msg := "scan job failed"
		if d := r.diagnoseJob(ctx, &job); d != "" {
			msg += ": " + d
		}
		l.Info("scan job failed", "job", job.Name, "reason", msg)
		return r.failScan(ctx, report, cfg, msg)
	default:
		// Surface why a scan is not progressing (unschedulable, image pull
		// problems, Pod Security or quota rejections) instead of a bare
		// "scan job started".
		msg := "scanning"
		if d := r.diagnoseJob(ctx, &job); d != "" {
			msg = "scan not progressing: " + d
		}
		r.setMessage(ctx, report, msg)
		return ctrl.Result{RequeueAfter: jobPollFallback}, nil
	}
}

func (r *DepScanReportReconciler) ingest(ctx context.Context, report *depscanv1alpha1.DepScanReport, job *batchv1.Job, cfg depscanv1alpha1.DepScanConfigSpec, jobNS string) (ctrl.Result, error) {
	logs, err := r.jobPodLogs(ctx, jobNS, job)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("read scan logs: %w", err)
	}
	vdrJSON, csafJSON := scan.ExtractReports(logs, job.Annotations[scan.AnnotationMarkerNonce])

	// Fail closed: a missing or non-CycloneDX VDR means the scan result is
	// unknown, never "no findings".
	if vdrJSON == "" {
		msg := "dep-scan produced no VDR report"
		if len(logs) >= maxScanLogBytes {
			msg += fmt.Sprintf(" (scan output exceeds the %d MiB read limit)", maxScanLogBytes>>20)
		}
		return r.failScan(ctx, report, cfg, msg)
	}
	if !scan.IsCycloneDX([]byte(vdrJSON)) {
		return r.failScan(ctx, report, cfg, "dep-scan VDR report is not a CycloneDX document")
	}
	result, parseErr := scan.ParseReports([]byte(vdrJSON), []byte(csafJSON))
	if parseErr != nil {
		return r.failScan(ctx, report, cfg, fmt.Sprintf("parse dep-scan output: %v", parseErr))
	}

	report.Status.Phase = depscanv1alpha1.PhaseCompleted
	vulns := capVulnerabilities(result.Vulnerabilities)
	truncated := len(result.Vulnerabilities) - len(vulns)
	report.Status.Vulnerabilities = vulns
	report.Status.Summary = result.Summary
	report.Status.ReachabilityAnalyzed = result.ReachabilityAnalyzed
	report.Status.Message = reachabilityMessage(len(result.Vulnerabilities), result.Summary, result.ReachabilityAnalyzed)
	if truncated > 0 {
		report.Status.Message += fmt.Sprintf("; %d lowest-severity findings omitted from status", truncated)
	}
	now := metav1.Now()
	report.Status.UpdateTimestamp = &now

	report.Status.Exported = false
	report.Status.ConsecutiveFailures = 0

	// Persist the result before any side effect: a status conflict retries
	// the whole ingest, which must not re-upload to DefectDojo or double
	// count metrics.
	if err := r.Status().Update(ctx, report); err != nil {
		return ctrl.Result{}, err
	}
	metrics.ScansCompleted.WithLabelValues("completed").Inc()
	r.event(report, corev1.EventTypeNormal, "ScanCompleted", "Scan", "%s", report.Status.Message)
	if job.Status.StartTime != nil {
		metrics.ScanDurationSeconds.Observe(now.Sub(job.Status.StartTime.Time).Seconds())
	}
	r.recomputeVulnerabilityGauges(ctx)

	if cfg.DefectDojo != nil && cfg.DefectDojo.Enabled {
		r.exportResult(ctx, report, cfg, csafJSON)
	}
	return ctrl.Result{RequeueAfter: cfg.RescanInterval.Duration}, nil
}

// exportResult uploads the CSAF report to DefectDojo and records the outcome
// with a status patch. Upload errors (which may echo the server's response)
// go to the operator log; the tenant-visible status only names the failure.
func (r *DepScanReportReconciler) exportResult(ctx context.Context, report *depscanv1alpha1.DepScanReport, cfg depscanv1alpha1.DepScanConfigSpec, csafJSON string) {
	base := report.DeepCopy()
	switch err := r.exportToDefectDojo(ctx, report, cfg, csafJSON); {
	case strings.TrimSpace(csafJSON) == "":
		report.Status.Message += "; defectdojo export skipped: dep-scan produced no CSAF report"
		metrics.ReportsExported.WithLabelValues("failed").Inc()
	case err != nil:
		log.FromContext(ctx).Error(err, "defectdojo export failed")
		report.Status.Message += "; defectdojo export failed" + defectdojo.Describe(err) + " (see operator logs)"
		r.event(report, corev1.EventTypeWarning, "ExportFailed", "Export", "DefectDojo export failed%s", defectdojo.Describe(err))
		metrics.ReportsExported.WithLabelValues("failed").Inc()
	default:
		report.Status.Exported = true
		metrics.ReportsExported.WithLabelValues("completed").Inc()
	}
	if err := r.Status().Patch(ctx, report, client.MergeFrom(base)); err != nil {
		log.FromContext(ctx).Error(err, "record defectdojo export outcome")
	}
}

// capVulnerabilities keeps the leading findings (sorted by severity, highest
// first) within maxStoredVulnerabilities and maxStoredVulnerabilityBytes.
func capVulnerabilities(vulns []depscanv1alpha1.Vulnerability) []depscanv1alpha1.Vulnerability {
	size := 0
	for i := range vulns {
		if i >= maxStoredVulnerabilities {
			return vulns[:i]
		}
		b, err := json.Marshal(&vulns[i])
		if err != nil {
			return vulns[:i]
		}
		size += len(b) + 1
		if size > maxStoredVulnerabilityBytes {
			return vulns[:i]
		}
	}
	return vulns
}

// AnnotationRescan on a DepScanReport requests an immediate rescan
// (`kubectl annotate dsr <name> depscan.io/rescan=now`). The operator removes
// it once handled.
const AnnotationRescan = "depscan.io/rescan"

// handleRescanRequest consumes the rescan annotation: a finished report goes
// back to Pending (scanned on the next pass, retry backoff reset); a report
// that is already pending or scanning is left alone.
func (r *DepScanReportReconciler) handleRescanRequest(ctx context.Context, report *depscanv1alpha1.DepScanReport) (ctrl.Result, error) {
	base := report.DeepCopy()
	delete(report.Annotations, AnnotationRescan)
	if err := r.Patch(ctx, report, client.MergeFrom(base)); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	switch report.Status.Phase {
	case depscanv1alpha1.PhaseCompleted, depscanv1alpha1.PhaseFailed:
		report.Status.Phase = depscanv1alpha1.PhasePending
		report.Status.ConsecutiveFailures = 0
		report.Status.Message = "rescan requested"
		if err := r.Status().Update(ctx, report); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{RequeueAfter: time.Second}, nil
}

// backfillSummary fills summary counts added after a report was scanned
// (totalCount, reachable critical/high) from its stored findings, so existing
// reports show them without waiting for a rescan. Stored findings keep the
// highest severities first, so the reachable critical/high counts are exact.
func (r *DepScanReportReconciler) backfillSummary(ctx context.Context, report *depscanv1alpha1.DepScanReport) {
	s := &report.Status.Summary
	if s.TotalCount != 0 || len(report.Status.Vulnerabilities) == 0 {
		return
	}
	base := report.DeepCopy()
	s.TotalCount = s.CriticalCount + s.HighCount + s.MediumCount + s.LowCount + s.NoneCount + s.UnknownCount
	s.ReachableCriticalCount, s.ReachableHighCount = 0, 0
	for _, v := range report.Status.Vulnerabilities {
		if v.Reachability != depscanv1alpha1.ReachabilityReachable {
			continue
		}
		switch v.Severity {
		case depscanv1alpha1.SeverityCritical:
			s.ReachableCriticalCount++
		case depscanv1alpha1.SeverityHigh:
			s.ReachableHighCount++
		}
	}
	// A full update (not a merge patch) writes every count, zeros included,
	// so objects from older versions end up with a complete summary.
	if err := r.Status().Update(ctx, report); err != nil {
		if !apierrors.IsConflict(err) {
			log.FromContext(ctx).Error(err, "backfill report summary")
		}
		report.Status = base.Status
	}
}

// requeueOnConflict turns an optimistic-concurrency conflict (another writer
// updated the object first, e.g. the pod controller) into a quiet retry
// instead of an error-level "Reconciler error" log line.
func requeueOnConflict(res ctrl.Result, err error) (ctrl.Result, error) {
	if apierrors.IsConflict(err) {
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}
	return res, err
}

// setMessage updates the status message when it changed (best effort; a
// conflict is retried on the next reconcile).
func (r *DepScanReportReconciler) setMessage(ctx context.Context, report *depscanv1alpha1.DepScanReport, msg string) {
	if report.Status.Message == msg {
		return
	}
	base := report.DeepCopy()
	report.Status.Message = msg
	_ = r.Status().Patch(ctx, report, client.MergeFrom(base))
}

// failScan marks a finished scan Failed (the Job failed, or its output could
// not be trusted) and schedules a retry with backoff.
func (r *DepScanReportReconciler) failScan(ctx context.Context, report *depscanv1alpha1.DepScanReport, cfg depscanv1alpha1.DepScanConfigSpec, msg string) (ctrl.Result, error) {
	report.Status.Phase = depscanv1alpha1.PhaseFailed
	report.Status.ConsecutiveFailures++
	retry := retryDelay(cfg, report.Status.ConsecutiveFailures)
	report.Status.Message = fmt.Sprintf("%s; retrying in %s", msg, retry)
	now := metav1.Now()
	report.Status.UpdateTimestamp = &now
	if err := r.Status().Update(ctx, report); err != nil {
		return ctrl.Result{}, err
	}
	metrics.ScansCompleted.WithLabelValues("failed").Inc()
	r.event(report, corev1.EventTypeWarning, "ScanFailed", "Scan", "%s", report.Status.Message)
	return ctrl.Result{RequeueAfter: retry}, nil
}

// event records a Kubernetes Event on obj when a recorder is configured.
// Notes are capped at the API's 1 KiB limit.
func (r *DepScanReportReconciler) event(obj runtime.Object, eventtype, reason, action, note string, args ...any) {
	if r.Recorder == nil {
		return
	}
	r.Recorder.Eventf(obj, nil, eventtype, reason, action, "%s", truncateDiagnosis(fmt.Sprintf(note, args...)))
}

// retryDelay is the wait after the n-th consecutive failed scan: 5m doubling,
// capped at the rescan interval (transient registry or node problems should
// not cost a full rescan interval).
func retryDelay(cfg depscanv1alpha1.DepScanConfigSpec, failures int32) time.Duration {
	d := 5 * time.Minute
	for i := int32(1); i < failures && d < cfg.RescanInterval.Duration; i++ {
		d *= 2
	}
	if d > cfg.RescanInterval.Duration {
		d = cfg.RescanInterval.Duration
	}
	return d
}

func (r *DepScanReportReconciler) maybeRescan(ctx context.Context, report *depscanv1alpha1.DepScanReport, cfg depscanv1alpha1.DepScanConfigSpec, jobNS string) (ctrl.Result, error) {
	r.backfillSummary(ctx, report)
	last := report.Status.UpdateTimestamp
	if last == nil {
		return r.startScan(ctx, report, cfg, jobNS)
	}
	wait := cfg.RescanInterval.Duration
	if report.Status.Phase == depscanv1alpha1.PhaseFailed {
		wait = retryDelay(cfg, report.Status.ConsecutiveFailures)
	}
	due := last.Add(wait)
	if time.Now().After(due) {
		report.Status.Phase = depscanv1alpha1.PhasePending
		if err := r.Status().Update(ctx, report); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}
	return ctrl.Result{RequeueAfter: time.Until(due)}, nil
}

func (r *DepScanReportReconciler) exportToDefectDojo(ctx context.Context, report *depscanv1alpha1.DepScanReport, cfg depscanv1alpha1.DepScanConfigSpec, csafJSON string) error {
	if strings.TrimSpace(csafJSON) == "" {
		return nil // nothing to upload; the caller reports the skip
	}
	dd := cfg.DefectDojo
	secretNS := dd.CredentialsSecret.Namespace
	if secretNS == "" {
		secretNS = r.OperatorNamespace
	}
	var secret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: secretNS, Name: dd.CredentialsSecret.Name}, &secret); err != nil {
		return fmt.Errorf("read credentials secret: %w", err)
	}
	username := string(secret.Data["username"])
	password := string(secret.Data["password"])
	token := string(secret.Data["token"])
	if token == "" && password == "" {
		return fmt.Errorf("credentials secret %s/%s needs a 'token' or 'password'", secretNS, dd.CredentialsSecret.Name)
	}

	uploader := defectdojo.New(dd.URL, username, password)
	uploader.Token = token
	uploader.AllowInsecure = dd.AllowInsecureURL
	productName := renderProductName(dd.ProductNameTemplate, report.Namespace, report.Spec.Image)

	return uploader.Reimport(ctx, defectdojo.ReimportParams{
		ScanType:         dd.ScanType,
		ProductName:      productName,
		ProductType:      dd.ProductType,
		EngagementName:   dd.EngagementName,
		TestTitle:        report.Spec.Image,
		Filename:         naming.ReportName(report.Spec.Image) + ".csaf.json",
		Report:           []byte(csafJSON),
		CloseOldFindings: dd.CloseOldFindings,
	})
}

func (r *DepScanReportReconciler) jobPodLogs(ctx context.Context, ns string, job *batchv1.Job) (string, error) {
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(ns), client.MatchingLabels{
		"job-name": job.Name,
	}); err != nil {
		return "", err
	}
	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no pods found for job %s", job.Name)
	}
	pod := pods.Items[0]
	for i := range pods.Items {
		if pods.Items[i].CreationTimestamp.After(pod.CreationTimestamp.Time) {
			pod = pods.Items[i]
		}
	}
	req := r.Clientset.CoreV1().Pods(ns).GetLogs(pod.Name, &corev1.PodLogOptions{})
	stream, err := req.Stream(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = stream.Close() }()
	// Scan logs are attacker-influenceable (filenames/strings from the target
	// image reach dep-scan's output); bound the read to protect the CRD/etcd.
	data, err := io.ReadAll(io.LimitReader(stream, maxScanLogBytes))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ensureDockerConfigSecret builds a dockerconfigjson Secret in the job
// namespace holding the registry credentials for this image, with wildcard
// registry auth resolved to the image's concrete host. Returns "" when the
// workload has no usable pull secrets (anonymous pull).
func (r *DepScanReportReconciler) ensureDockerConfigSecret(ctx context.Context, report *depscanv1alpha1.DepScanReport, jobNS string) (string, error) {
	var payloads [][]byte
	for _, secretName := range report.Spec.ImagePullSecrets {
		var src corev1.Secret
		if err := r.Get(ctx, types.NamespacedName{Namespace: report.Namespace, Name: secretName}, &src); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return "", err
		}
		if data, ok := src.Data[corev1.DockerConfigJsonKey]; ok {
			payloads = append(payloads, data)
		}
	}

	configJSON, ok := dockercfg.Build(report.Spec.Image, payloads)
	if !ok {
		return "", nil
	}

	name := scanCredentialsSecretName(report.Namespace, report.Name)
	desired := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: jobNS,
			Labels:    map[string]string{depscanv1alpha1.LabelManagedBy: depscanv1alpha1.ManagedByValue},
		},
		Type: corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{corev1.DockerConfigJsonKey: configJSON},
	}
	if err := r.Create(ctx, &desired); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return "", err
		}
		var cur corev1.Secret
		if err := r.reader().Get(ctx, types.NamespacedName{Namespace: jobNS, Name: name}, &cur); err != nil {
			return "", err
		}
		if cur.Labels[depscanv1alpha1.LabelManagedBy] != depscanv1alpha1.ManagedByValue {
			return "", fmt.Errorf("secret %s/%s exists but is not managed by the operator", jobNS, name)
		}
		cur.Type = desired.Type
		cur.Data = desired.Data
		if err := r.Update(ctx, &cur); err != nil {
			return "", err
		}
	}
	return name, nil
}

// jobFinished reports whether a Job reached a terminal state: complete (a pod
// succeeded) or failed (Failed condition, or retries exhausted).
func jobFinished(job *batchv1.Job) (complete, failed bool) {
	if job.Status.Succeeded > 0 {
		return true, false
	}
	for _, c := range job.Status.Conditions {
		if c.Status != corev1.ConditionTrue {
			continue
		}
		switch c.Type {
		case batchv1.JobComplete:
			return true, false
		case batchv1.JobFailed:
			return false, true
		}
	}
	limit := int32(6) // Kubernetes default backoffLimit
	if job.Spec.BackoffLimit != nil {
		limit = *job.Spec.BackoffLimit
	}
	return false, job.Status.Failed > limit
}

// deleteScanCredentials removes the per-report registry credentials Secret
// from the job namespace, if the operator owns it.
func deleteScanCredentials(ctx context.Context, c client.Client, rd client.Reader, jobNS string, report *depscanv1alpha1.DepScanReport) {
	name := scanCredentialsSecretName(report.Namespace, report.Name)
	var secret corev1.Secret
	if err := rd.Get(ctx, client.ObjectKey{Namespace: jobNS, Name: name}, &secret); err != nil {
		return
	}
	if secret.Labels[depscanv1alpha1.LabelManagedBy] == depscanv1alpha1.ManagedByValue {
		if err := client.IgnoreNotFound(c.Delete(ctx, &secret)); err != nil {
			log.FromContext(ctx).Error(err, "delete scan credentials", "secret", name)
		}
	}
}

// createWithinCapacity creates the scan Job unless maxConcurrentScans scan
// Jobs are already active, returning whether it was created. The count is
// read uncached and the check-and-create is serialized, so neither cache lag
// nor parallel reconciles can overshoot the limit.
//
// It also returns the number of active scans when the limit was reached.
func (r *DepScanReportReconciler) createWithinCapacity(ctx context.Context, job *batchv1.Job, jobNS string, limit int32) (bool, int32, error) {
	r.scanSlotMu.Lock()
	defer r.scanSlotMu.Unlock()
	if limit > 0 {
		active, err := r.activeScans(ctx, jobNS)
		if err != nil {
			return false, 0, err
		}
		if active >= limit {
			return false, active, nil
		}
	}
	if err := r.Create(ctx, job); err != nil && !apierrors.IsAlreadyExists(err) {
		return false, 0, fmt.Errorf("create scan job: %w", err)
	}
	return true, 0, nil
}

// atScanCapacity reports whether the number of active (not yet finished)
// scan Jobs in the job namespace is at or above the limit. VDB prime/GC Jobs
// (which carry a component label) do not take scan slots.
func (r *DepScanReportReconciler) atScanCapacity(ctx context.Context, jobNS string, limit int32) (bool, error) {
	if limit <= 0 {
		return false, nil
	}
	active, err := r.activeScans(ctx, jobNS)
	return active >= limit, err
}

// activeScans counts unfinished scan Jobs, read uncached.
func (r *DepScanReportReconciler) activeScans(ctx context.Context, jobNS string) (int32, error) {
	var jobs batchv1.JobList
	if err := r.reader().List(ctx, &jobs, client.InNamespace(jobNS),
		client.MatchingLabels{depscanv1alpha1.LabelManagedBy: depscanv1alpha1.ManagedByValue}); err != nil {
		return 0, err
	}
	active := int32(0)
	for i := range jobs.Items {
		j := &jobs.Items[i]
		if j.Labels[depscanv1alpha1.LabelComponent] != "" {
			continue
		}
		if complete, failed := jobFinished(j); !complete && !failed {
			active++
		}
	}
	return active, nil
}

func (r *DepScanReportReconciler) deleteScanJob(ctx context.Context, ns, name string) error {
	var job batchv1.Job
	if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &job); err != nil {
		return client.IgnoreNotFound(err)
	}
	policy := metav1.DeletePropagationBackground
	return client.IgnoreNotFound(r.Delete(ctx, &job, &client.DeleteOptions{PropagationPolicy: &policy}))
}

func (r *DepScanReportReconciler) jobNamespace(cfg depscanv1alpha1.DepScanConfigSpec) string {
	return JobNamespace(cfg, r.OperatorNamespace)
}

// JobNamespace is where scan, prime and GC Jobs (and their Secrets, PVC and
// state) live: the configured jobNamespace, else the operator namespace.
func JobNamespace(cfg depscanv1alpha1.DepScanConfigSpec, operatorNamespace string) string {
	if cfg.JobNamespace != "" {
		return cfg.JobNamespace
	}
	return operatorNamespace
}

const defaultVDBClaimName = "depscan-vdb-cache"

// ensureVDBClaim returns the PVC name to mount at VDB_HOME, provisioning a
// shared cache PVC when caching is enabled without an explicit claim. Returns
// "" when caching is disabled (the Job then uses an emptyDir).
//
// The access mode defaults to ReadWriteOnce, which only works while every
// prime, GC and scan pod lands on the node the volume is attached to: a pod
// scheduled elsewhere cannot attach it and stays in ContainerCreating
// (Multi-Attach error) until it hits its deadline. Multi-node clusters need
// ReadWriteMany.
func (r *DepScanReportReconciler) ensureVDBClaim(ctx context.Context, cfg depscanv1alpha1.DepScanConfigSpec, jobNS string) (string, error) {
	if cfg.VDBCache == nil || !cfg.VDBCache.Enabled {
		return "", nil
	}
	if cfg.VDBCache.ClaimName != "" {
		return cfg.VDBCache.ClaimName, nil
	}

	name := defaultVDBClaimName
	var existing corev1.PersistentVolumeClaim
	err := r.Get(ctx, types.NamespacedName{Namespace: jobNS, Name: name}, &existing)
	if err == nil {
		return name, nil
	}
	if !apierrors.IsNotFound(err) {
		return "", err
	}

	size := cfg.VDBCache.Size
	if size == "" {
		size = depscanv1alpha1.DefaultVDBCacheSize
	}
	qty, err := resource.ParseQuantity(size)
	if err != nil {
		return "", fmt.Errorf("parse vdbCache size %q: %w", size, err)
	}

	accessMode := corev1.ReadWriteOnce
	if cfg.VDBCache.AccessMode == string(corev1.ReadWriteMany) {
		accessMode = corev1.ReadWriteMany
	}

	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: jobNS,
			Labels: map[string]string{
				depscanv1alpha1.LabelManagedBy: depscanv1alpha1.ManagedByValue,
			},
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{accessMode},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceStorage: qty},
			},
		},
	}
	if sc := cfg.VDBCache.StorageClassName; sc != "" {
		pvc.Spec.StorageClassName = &sc
	}
	if err := r.Create(ctx, pvc); err != nil && !apierrors.IsAlreadyExists(err) {
		return "", fmt.Errorf("create vdb cache PVC: %w", err)
	}
	return name, nil
}

// scanCredentialsSecretName is the stable, collision-safe name of the
// per-report credentials Secret in the job namespace. A hash suffix keeps it
// unique within the 253-char limit.
func scanCredentialsSecretName(namespace, reportName string) string {
	sum := sha256.Sum256([]byte(namespace + "/" + reportName))
	suffix := hex.EncodeToString(sum[:])[:12]
	prefix := fmt.Sprintf("depscan-creds-%s-%s", namespace, reportName)
	if len(prefix) > 200 {
		prefix = prefix[:200]
	}
	return prefix + "-" + suffix
}

// scanPlatform picks the os/arch to pull: the config override, else the
// platform of the node the image runs on, else BuildJob's linux/amd64.
func scanPlatform(cfg depscanv1alpha1.DepScanConfigSpec, report *depscanv1alpha1.DepScanReport) string {
	if cfg.Platform != "" {
		return cfg.Platform
	}
	return report.Spec.Platform
}

// randomHex returns n random bytes, hex-encoded.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func renderProductName(tmpl, namespace, image string) string {
	if tmpl == "" {
		tmpl = "{namespace}"
	}
	out := strings.ReplaceAll(tmpl, "{namespace}", namespace)
	out = strings.ReplaceAll(out, "{image}", image)
	return out
}

// recomputeVulnerabilityGauges rebuilds the per-namespace, per-severity CVE
// gauges from the current set of reports. It sums every report's summary into
// namespace totals and replaces the gauge wholesale, so counts for deleted
// reports or namespaces drop out. Deliberately low-cardinality (no per-image
// label) to stay safe for time-series stores like InfluxDB.
func (r *DepScanReportReconciler) recomputeVulnerabilityGauges(ctx context.Context) {
	var reports depscanv1alpha1.DepScanReportList
	if err := r.List(ctx, &reports); err != nil {
		log.FromContext(ctx).Error(err, "list reports for vulnerability gauges")
		return
	}
	setVulnerabilityGaugesFromReports(reports.Items)
}

// setVulnerabilityGaugesFromReports aggregates report summaries by namespace
// and severity and publishes them as the vulnerability gauge.
// reachabilityMessage renders a concise status message that does not conflate
// "none reachable" with "reachability not analyzed". When analysis ran it
// reports the reachable / not-reachable split; otherwise it states that
// reachability was not analyzed.
func reachabilityMessage(total int, s depscanv1alpha1.VulnerabilitySummary, analyzed bool) string {
	if !analyzed {
		return fmt.Sprintf("%d findings (reachability not analyzed)", total)
	}
	return fmt.Sprintf("%d findings (%d reachable, %d not-reachable, %d undetermined)",
		total, s.ReachableCount, s.NotReachableCount, s.UnknownReachabilityCount)
}

func setVulnerabilityGaugesFromReports(reports []depscanv1alpha1.DepScanReport) {
	totals := map[string]map[string]int{}
	reach := map[string]map[string]int{}
	phases := map[string]int{}
	for i := range reports {
		rep := &reports[i]
		phase := string(rep.Status.Phase)
		if phase == "" {
			phase = string(depscanv1alpha1.PhasePending)
		}
		phases[phase]++
		ns := totals[rep.Namespace]
		if ns == nil {
			ns = map[string]int{}
			totals[rep.Namespace] = ns
		}
		s := rep.Status.Summary
		ns["critical"] += s.CriticalCount
		ns["high"] += s.HighCount
		ns["medium"] += s.MediumCount
		ns["low"] += s.LowCount
		ns["none"] += s.NoneCount
		ns["unknown"] += s.UnknownCount

		rs := reach[rep.Namespace]
		if rs == nil {
			rs = map[string]int{}
			reach[rep.Namespace] = rs
		}
		rs["reachable"] += s.ReachableCount
		rs["not_reachable"] += s.NotReachableCount
		rs["unknown"] += s.UnknownReachabilityCount
	}
	metrics.SetNamespaceVulnerabilityGauges(totals)
	metrics.SetNamespaceReachabilityGauges(reach)
	metrics.SetReportPhases(phases)
}

func (r *DepScanReportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&depscanv1alpha1.DepScanReport{}).
		Named("depscanreport").
		// Scan Jobs live in another namespace, so owner references cannot be
		// used; map Job events back to the report via its labels instead of
		// polling every scan.
		Watches(&batchv1.Job{}, handler.EnqueueRequestsFromMapFunc(reportForJob)).
		WithOptions(controller.Options{MaxConcurrentReconciles: r.MaxConcurrentReconciles}).
		Complete(r)
}

// reportForJob maps a scan Job to the DepScanReport it serves.
func reportForJob(_ context.Context, obj client.Object) []reconcile.Request {
	l := obj.GetLabels()
	ns, name := l[scan.LabelReportNamespace], l[scan.LabelReportName]
	if l[depscanv1alpha1.LabelManagedBy] != depscanv1alpha1.ManagedByValue || ns == "" || name == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}}}
}
