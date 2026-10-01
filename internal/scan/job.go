package scan

import (
	"fmt"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
	"github.com/mgerhardy/k8s-depscan-operator/internal/naming"
)

// Markers delimit the report payloads in the scan pod's stdout, so the
// operator can read them from the Job logs without shared storage.
const (
	VDRBegin  = "---DEPSCAN-VDR-BEGIN---"
	VDREnd    = "---DEPSCAN-VDR-END---"
	CSAFBegin = "---DEPSCAN-CSAF-BEGIN---"
	CSAFEnd   = "---DEPSCAN-CSAF-END---"

	reportsDir = "/reports"
	vdbHome    = "/vdb"
	workDir    = "/work"
	imageTar   = "/work/image.tar"
	dockerCfg  = "/dockercfg"

	// DefaultCraneImage pulls images over the OCI Distribution API without a
	// container runtime, so it works against any registry on any cluster.
	DefaultCraneImage = depscanv1alpha1.DefaultCraneImage
)

type JobConfig struct {
	Image        string
	ScannerImage string
	CraneImage   string
	Profile      string // dep-scan --profile (e.g. "research" for reachability)
	Namespace    string
	TTLSeconds   int32
	VDBClaim     string // PVC name for the VDB cache; empty uses an emptyDir
	VDBVersion   string // cached VDB version dir to pin this scan to (requires VDBClaim)
	// Scope must match the scope the VDB was primed with (--vdb-scope on the
	// scan). When the primed cache is a pinned read-only version, a scope or
	// staleness mismatch makes dep-scan try to re-download onto the read-only
	// mount and fail; matching the scope (and treating the cache as fresh)
	// keeps the scan read-only. Empty uses dep-scan's default (app+os).
	Scope       string
	Resources   *depscanv1alpha1.ResourceRequirements
	OwnerLabels map[string]string
	// DockerConfigSecret names a kubernetes.io/dockerconfigjson Secret the
	// operator built for this image (with wildcard registry auth resolved to
	// the concrete host). Mounted for crane via DOCKER_CONFIG. Empty means
	// anonymous pulls.
	DockerConfigSecret string
	Platform           string // e.g. "linux/amd64"; defaults to linux/amd64
	// Timeout sets the Job's activeDeadlineSeconds; zero means no deadline.
	Timeout time.Duration
	// WorkSizeLimit caps the image-archive scratch emptyDir; nil means
	// unlimited.
	WorkSizeLimit *resource.Quantity
	// VDBSizeLimit caps the per-scan VDB emptyDir used when there is no cache
	// PVC; nil means unlimited.
	VDBSizeLimit *resource.Quantity
	// MarkerNonce is a random per-Job value embedded in the report markers
	// (see Markers) and recorded in the AnnotationMarkerNonce annotation.
	MarkerNonce string
}

// LabelReportNamespace and LabelReportName (set via OwnerLabels) tie a scan
// Job to its DepScanReport.
const (
	LabelReportNamespace = "depscan.io/report-namespace"
	LabelReportName      = "depscan.io/report-name"
)

// AnnotationMarkerNonce records the scan Job's report-marker nonce.
const AnnotationMarkerNonce = "depscan.io/marker-nonce"

// BuildJob builds a Job that pulls the image to a local OCI archive with crane
// and then runs dep-scan against that archive, emitting the VDR and CSAF
// reports between markers for log-based ingestion. Pulling via crane rather
// than a node runtime is what keeps image access cluster-agnostic.
func BuildJob(cfg JobConfig) *batchv1.Job {
	name := naming.JobName(cfg.OwnerLabels[LabelReportNamespace], cfg.Image)
	craneImage := cfg.CraneImage
	if craneImage == "" {
		craneImage = DefaultCraneImage
	}
	platform := cfg.Platform
	if platform == "" {
		platform = "linux/amd64"
	}
	profile := cfg.Profile
	if profile == "" {
		profile = "research"
	}

	labels := map[string]string{
		depscanv1alpha1.LabelManagedBy:   depscanv1alpha1.ManagedByValue,
		depscanv1alpha1.LabelImageDigest: naming.ImageKey(cfg.Image),
	}
	if cfg.VDBVersion != "" {
		labels[depscanv1alpha1.LabelVDBVersion] = cfg.VDBVersion
	}
	for k, v := range cfg.OwnerLabels {
		labels[k] = v
	}

	reportsLimit := resource.MustParse("1Gi")
	volumes := []corev1.Volume{
		{Name: "work", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: cfg.WorkSizeLimit}}},
		{Name: "reports", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &reportsLimit}}},
	}
	// vdbMount is where the scan container reads the VDB. With a shared cache
	// it is a specific version subdir (read-only); otherwise a fresh emptyDir.
	vdbMount := corev1.VolumeMount{Name: "vdb", MountPath: vdbHome}
	if cfg.VDBClaim != "" {
		volumes = append(volumes, corev1.Volume{
			Name: "vdb",
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: cfg.VDBClaim, ReadOnly: true},
			},
		})
		if cfg.VDBVersion != "" {
			vdbMount = corev1.VolumeMount{Name: "vdb", MountPath: vdbHome, SubPath: cfg.VDBVersion, ReadOnly: true}
		}
	} else {
		volumes = append(volumes, corev1.Volume{
			Name:         "vdb",
			VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: cfg.VDBSizeLimit}},
		})
	}

	// --- Init container: crane pulls the image to a local OCI archive. ---
	craneEnv := []corev1.EnvVar{}
	craneMounts := []corev1.VolumeMount{{Name: "work", MountPath: workDir}}

	// The operator builds a config.json (resolving wildcard registry auth to
	// this image's concrete host) and stores it in DockerConfigSecret. crane
	// reads it via DOCKER_CONFIG. Empty means anonymous pulls.
	if cfg.DockerConfigSecret != "" {
		volumes = append(volumes, corev1.Volume{
			Name: "dockercfg",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: cfg.DockerConfigSecret,
					Items: []corev1.KeyToPath{
						{Key: corev1.DockerConfigJsonKey, Path: "config.json"},
					},
				},
			},
		})
		craneMounts = append(craneMounts, corev1.VolumeMount{Name: "dockercfg", MountPath: dockerCfg, ReadOnly: true})
		craneEnv = append(craneEnv, corev1.EnvVar{Name: "DOCKER_CONFIG", Value: dockerCfg})
	}

	initContainers := []corev1.Container{{
		Name:  "fetch-image",
		Image: craneImage,
		// "--" ends flag parsing so an image reference can never be read as a
		// crane flag.
		Command:         []string{"/ko-app/crane", "pull", "--platform", platform, "--", cfg.Image, imageTar},
		Env:             craneEnv,
		VolumeMounts:    craneMounts,
		ImagePullPolicy: corev1.PullIfNotPresent,
	}}

	// When the scan runs against a pinned read-only VDB version, it must
	// resolve the same scope the cache was primed with; otherwise dep-scan
	// detects a variant change and tries to re-download onto the read-only
	// mount (which fails). Empty scope leaves dep-scan's default.
	scopeFlag := ""
	if cfg.Scope != "" {
		scopeFlag = " --vdb-scope " + cfg.Scope
	}

	vdrBegin, vdrEnd, csafBegin, csafEnd := Markers(cfg.MarkerNonce)
	script := fmt.Sprintf(`set -e
mkdir -p %[1]s
echo "[depscan-operator] scanning image: ${SCAN_IMAGE} (from local archive)"
rc=0
depscan --src %[6]s -o %[1]s -t docker --profile %[7]s%[8]s --csaf --no-banner --no-vuln-table || rc=$?
# Emit whatever reports were produced so the operator can read them, then
# propagate a non-zero dep-scan exit so the Job fails instead of looking clean.
# A missing report is emitted as nothing (not "{}") so the operator fails the
# scan rather than recording zero findings.
echo "%[2]s"
cat %[1]s/*.vdr.json 2>/dev/null || true
echo ""
echo "%[3]s"
echo "%[4]s"
cat %[1]s/*.csaf.json 2>/dev/null || true
echo ""
echo "%[5]s"
if [ "$rc" -ne 0 ]; then
  echo "[depscan-operator] depscan exited non-zero (rc=$rc)" >&2
  exit "$rc"
fi
`, reportsDir, vdrBegin, vdrEnd, csafBegin, csafEnd, imageTar, profile, scopeFlag)

	depscanContainer := corev1.Container{
		Name:    "depscan",
		Image:   cfg.ScannerImage,
		Command: []string{"/bin/sh", "-c", script},
		Env: []corev1.EnvVar{
			// The image reference reaches the shell only as data, never as
			// script text.
			{Name: "SCAN_IMAGE", Value: cfg.Image},
			{Name: "VDB_HOME", Value: vdbHome},
			{Name: "DEPSCAN_NO_BANNER", Value: "true"},
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: "work", MountPath: workDir},
			{Name: "reports", MountPath: reportsDir},
			vdbMount,
		},
		ImagePullPolicy: corev1.PullIfNotPresent,
		SecurityContext: hardenedContainerSecurityContext(),
	}
	// With a pinned read-only cache version, the operator owns VDB freshness
	// (via its own refresh cycle), so stop dep-scan from treating the cache as
	// stale and attempting a re-download onto the read-only mount.
	if cfg.VDBClaim != "" && cfg.VDBVersion != "" {
		depscanContainer.Env = append(depscanContainer.Env, corev1.EnvVar{Name: "VDB_AGE_HOURS", Value: "876000"})
	}
	if res := buildResources(cfg.Resources); res != nil {
		depscanContainer.Resources = *res
	}
	for i := range initContainers {
		initContainers[i].SecurityContext = hardenedContainerSecurityContext()
	}

	var annotations map[string]string
	if cfg.MarkerNonce != "" {
		annotations = map[string]string{AnnotationMarkerNonce: cfg.MarkerNonce}
	}

	backoff := int32(1)
	ttl := cfg.TTLSeconds
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   cfg.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            &backoff,
			TTLSecondsAfterFinished: &ttl,
			ActiveDeadlineSeconds:   deadlineSeconds(cfg.Timeout),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					// The scan workload needs no API access.
					AutomountServiceAccountToken: boolPtr(false),
					SecurityContext: &corev1.PodSecurityContext{
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					InitContainers: initContainers,
					Containers:     []corev1.Container{depscanContainer},
					Volumes:        volumes,
					// dep-scan runs as root to read the VDB cache and unpacked
					// image layers, so runAsNonRoot is not enforced; privilege
					// escalation and extra capabilities are still blocked.
				},
			},
		},
	}
}

func buildResources(r *depscanv1alpha1.ResourceRequirements) *corev1.ResourceRequirements {
	if r == nil {
		return nil
	}
	out := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{},
		Limits:   corev1.ResourceList{},
	}
	for k, q := range r.Requests {
		out.Requests[corev1.ResourceName(k)] = q
	}
	for k, q := range r.Limits {
		out.Limits[corev1.ResourceName(k)] = q
	}
	if len(out.Requests) == 0 {
		out.Requests = nil
	}
	if len(out.Limits) == 0 {
		out.Limits = nil
	}
	return &out
}

func boolPtr(b bool) *bool { return &b }

// deadlineSeconds converts a timeout into activeDeadlineSeconds (nil for no
// deadline).
func deadlineSeconds(d time.Duration) *int64 {
	if d <= 0 {
		return nil
	}
	s := int64(d / time.Second)
	if s < 1 {
		s = 1
	}
	return &s
}

// hardenedContainerSecurityContext blocks privilege escalation and drops all
// capabilities. runAsNonRoot is intentionally not set: dep-scan needs root to
// read the VDB cache and unpacked image layers.
func hardenedContainerSecurityContext() *corev1.SecurityContext {
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: boolPtr(false),
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
}
