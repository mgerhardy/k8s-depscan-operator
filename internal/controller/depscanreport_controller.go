package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
	"github.com/mgerhardy/k8s-depscan-operator/internal/defectdojo"
	"github.com/mgerhardy/k8s-depscan-operator/internal/dockercfg"
	"github.com/mgerhardy/k8s-depscan-operator/internal/metrics"
	"github.com/mgerhardy/k8s-depscan-operator/internal/naming"
	"github.com/mgerhardy/k8s-depscan-operator/internal/scan"
)

const (
	// maxScanLogBytes bounds how much scan-pod log output is read into memory.
	maxScanLogBytes = 16 << 20 // 16 MiB
	// maxStoredVulnerabilities caps findings persisted in a report's status to
	// keep the object (and etcd) from being inflated by a pathological image.
	maxStoredVulnerabilities = 2000
)

// DepScanReportReconciler drives the scan lifecycle for a single report:
// create a Job, wait for completion, ingest the dep-scan output from the pod
// logs, update status, optionally export to DefectDojo, and rescan on an
// interval.
type DepScanReportReconciler struct {
	client.Client
	Clientset         kubernetes.Interface
	Config            *ConfigResolver
	OperatorNamespace string
}

// +kubebuilder:rbac:groups=depscan.io,resources=depscanreports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=depscan.io,resources=depscanreports/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=depscan.io,resources=depscanconfigs,verbs=get;list;watch
// +kubebuilder:rbac:groups=depscan.io,resources=depscanconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods/log,verbs=get
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update
// +kubebuilder:rbac:groups="",resources=persistentvolumeclaims,verbs=get;list;watch;create

func (r *DepScanReportReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

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
		l.Info("report namespace out of scope, deleting", "namespace", report.Namespace, "name", report.Name)
		return ctrl.Result{}, client.IgnoreNotFound(r.Delete(ctx, &report))
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
	vdbClaimName, err := r.ensureVDBClaim(ctx, cfg, jobNS)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("ensure vdb cache: %w", err)
	}

	// Build the registry credentials for this image (resolving wildcard auth to
	// the image's host) and store them in a job-namespace Secret for crane.
	dockerCfgSecret, err := r.ensureDockerConfigSecret(ctx, report, jobNS)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("prepare registry credentials: %w", err)
	}

	job := scan.BuildJob(scan.JobConfig{
		Image:              report.Spec.Image,
		ScannerImage:       cfg.ScannerImage,
		CraneImage:         cfg.CraneImage,
		Namespace:          jobNS,
		TTLSeconds:         cfg.JobTTLSeconds,
		VDBClaim:           vdbClaimName,
		Resources:          cfg.Resources,
		DockerConfigSecret: dockerCfgSecret,
		OwnerLabels: map[string]string{
			"depscan.io/report-namespace": report.Namespace,
			"depscan.io/report-name":      report.Name,
		},
	})

	existing := &batchv1.Job{}
	err = r.Get(ctx, types.NamespacedName{Namespace: jobNS, Name: job.Name}, existing)
	if apierrors.IsNotFound(err) {
		atCap, err := r.atScanCapacity(ctx, jobNS, cfg.MaxConcurrentScans)
		if err != nil {
			return ctrl.Result{}, err
		}
		if atCap {
			// Stay Pending and retry; another scan will free a slot.
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		if err := r.Create(ctx, job); err != nil && !apierrors.IsAlreadyExists(err) {
			return ctrl.Result{}, fmt.Errorf("create scan job: %w", err)
		}
	} else if err != nil {
		return ctrl.Result{}, err
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
	return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
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
		return ctrl.Result{Requeue: true}, nil
	}
	if err != nil {
		return ctrl.Result{}, err
	}

	switch {
	case job.Status.Succeeded > 0:
		return r.ingest(ctx, report, &job, cfg, jobNS)
	case job.Status.Failed > 0:
		report.Status.Phase = depscanv1alpha1.PhaseFailed
		report.Status.Message = "scan job failed"
		now := metav1.Now()
		report.Status.UpdateTimestamp = &now
		if err := r.Status().Update(ctx, report); err != nil {
			return ctrl.Result{}, err
		}
		metrics.ScansCompleted.WithLabelValues("failed").Inc()
		l.Info("scan job failed", "job", job.Name)
		return ctrl.Result{RequeueAfter: cfg.RescanInterval.Duration}, nil
	default:
		return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
	}
}

func (r *DepScanReportReconciler) ingest(ctx context.Context, report *depscanv1alpha1.DepScanReport, job *batchv1.Job, cfg depscanv1alpha1.DepScanConfigSpec, jobNS string) (ctrl.Result, error) {
	logs, err := r.jobPodLogs(ctx, jobNS, job)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("read scan logs: %w", err)
	}
	vdrJSON, csafJSON := scan.ExtractReports(logs)

	result, parseErr := scan.ParseVDR([]byte(nonEmptyJSON(vdrJSON)))
	if parseErr != nil {
		metrics.ScansCompleted.WithLabelValues("failed").Inc()
		report.Status.Phase = depscanv1alpha1.PhaseFailed
		report.Status.Message = fmt.Sprintf("parse dep-scan output: %v", parseErr)
		now := metav1.Now()
		report.Status.UpdateTimestamp = &now
		if err := r.Status().Update(ctx, report); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: cfg.RescanInterval.Duration}, nil
	}

	report.Status.Phase = depscanv1alpha1.PhaseCompleted
	vulns := result.Vulnerabilities
	truncated := 0
	if len(vulns) > maxStoredVulnerabilities {
		truncated = len(vulns) - maxStoredVulnerabilities
		vulns = vulns[:maxStoredVulnerabilities] // sorted by severity desc
	}
	report.Status.Vulnerabilities = vulns
	report.Status.Summary = result.Summary
	report.Status.Message = fmt.Sprintf("%d findings (%d reachable)", len(result.Vulnerabilities), result.Summary.ReachableCount)
	if truncated > 0 {
		report.Status.Message += fmt.Sprintf("; %d lowest-severity findings omitted from status", truncated)
	}
	now := metav1.Now()
	report.Status.UpdateTimestamp = &now

	metrics.ScansCompleted.WithLabelValues("completed").Inc()
	if job.Status.StartTime != nil {
		metrics.ScanDurationSeconds.Observe(now.Sub(job.Status.StartTime.Time).Seconds())
	}

	if cfg.DefectDojo != nil && cfg.DefectDojo.Enabled {
		if err := r.exportToDefectDojo(ctx, report, cfg, csafJSON); err != nil {
			log.FromContext(ctx).Error(err, "defectdojo export failed")
			report.Status.Message += fmt.Sprintf("; defectdojo export failed: %v", err)
			metrics.ReportsExported.WithLabelValues("failed").Inc()
		} else {
			report.Status.Exported = true
			metrics.ReportsExported.WithLabelValues("completed").Inc()
		}
	}

	if err := r.Status().Update(ctx, report); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: cfg.RescanInterval.Duration}, nil
}

func (r *DepScanReportReconciler) maybeRescan(ctx context.Context, report *depscanv1alpha1.DepScanReport, cfg depscanv1alpha1.DepScanConfigSpec, jobNS string) (ctrl.Result, error) {
	last := report.Status.UpdateTimestamp
	if last == nil {
		return r.startScan(ctx, report, cfg, jobNS)
	}
	due := last.Time.Add(cfg.RescanInterval.Duration)
	if time.Now().After(due) {
		report.Status.Phase = depscanv1alpha1.PhasePending
		if err := r.Status().Update(ctx, report); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}
	return ctrl.Result{RequeueAfter: time.Until(due)}, nil
}

func (r *DepScanReportReconciler) exportToDefectDojo(ctx context.Context, report *depscanv1alpha1.DepScanReport, cfg depscanv1alpha1.DepScanConfigSpec, csafJSON string) error {
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
		Report:           []byte(nonEmptyJSON(csafJSON)),
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
	defer stream.Close()
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
		if err := r.Get(ctx, types.NamespacedName{Namespace: jobNS, Name: name}, &cur); err == nil {
			cur.Data = desired.Data
			_ = r.Update(ctx, &cur)
		}
	}
	return name, nil
}

// atScanCapacity reports whether the number of active (not yet finished)
// managed scan Jobs in the job namespace is at or above the limit.
func (r *DepScanReportReconciler) atScanCapacity(ctx context.Context, jobNS string, limit int32) (bool, error) {
	if limit <= 0 {
		return false, nil
	}
	var jobs batchv1.JobList
	if err := r.List(ctx, &jobs, client.InNamespace(jobNS),
		client.MatchingLabels{depscanv1alpha1.LabelManagedBy: depscanv1alpha1.ManagedByValue}); err != nil {
		return false, err
	}
	active := int32(0)
	for i := range jobs.Items {
		j := &jobs.Items[i]
		if j.Status.Succeeded == 0 && j.Status.Failed == 0 {
			active++
		}
	}
	return active >= limit, nil
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
	if cfg.JobNamespace != "" {
		return cfg.JobNamespace
	}
	return r.OperatorNamespace
}

const defaultVDBClaimName = "depscan-vdb-cache"

// ensureVDBClaim returns the PVC name to mount at VDB_HOME, provisioning a
// shared cache PVC when caching is enabled without an explicit claim. Returns
// "" when caching is disabled (the Job then uses an emptyDir).
//
// The PVC is ReadWriteOnce: on a single node, concurrent scan pods can share
// it; pods scheduled to other nodes re-download the VDB for that run.
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
		size = "10Gi"
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

func renderProductName(tmpl, namespace, image string) string {
	if tmpl == "" {
		tmpl = "{namespace}"
	}
	out := strings.ReplaceAll(tmpl, "{namespace}", namespace)
	out = strings.ReplaceAll(out, "{image}", image)
	return out
}

func nonEmptyJSON(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "{}"
	}
	return s
}

func (r *DepScanReportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&depscanv1alpha1.DepScanReport{}).
		Named("depscanreport").
		Complete(r)
}
