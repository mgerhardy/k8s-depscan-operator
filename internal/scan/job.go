package scan

import (
	"fmt"

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
	DefaultCraneImage = "gcr.io/go-containerregistry/crane:latest"
)

type JobConfig struct {
	Image        string
	ScannerImage string
	CraneImage   string
	Namespace    string
	TTLSeconds   int32
	VDBClaim     string // PVC name for the VDB cache; empty uses an emptyDir
	Resources    *depscanv1alpha1.ResourceRequirements
	OwnerLabels  map[string]string
	// DockerConfigSecret names a kubernetes.io/dockerconfigjson Secret the
	// operator built for this image (with wildcard registry auth resolved to
	// the concrete host). Mounted for crane via DOCKER_CONFIG. Empty means
	// anonymous pulls.
	DockerConfigSecret string
	Platform           string // e.g. "linux/amd64"; defaults to linux/amd64
}

// BuildJob builds a Job that pulls the image to a local OCI archive with crane
// and then runs dep-scan against that archive, emitting the VDR and CSAF
// reports between markers for log-based ingestion. Pulling via crane rather
// than a node runtime is what keeps image access cluster-agnostic.
func BuildJob(cfg JobConfig) *batchv1.Job {
	name := naming.JobName(cfg.Image)
	craneImage := cfg.CraneImage
	if craneImage == "" {
		craneImage = DefaultCraneImage
	}
	platform := cfg.Platform
	if platform == "" {
		platform = "linux/amd64"
	}

	labels := map[string]string{
		depscanv1alpha1.LabelManagedBy:   depscanv1alpha1.ManagedByValue,
		depscanv1alpha1.LabelImageDigest: naming.ImageKey(cfg.Image),
	}
	for k, v := range cfg.OwnerLabels {
		labels[k] = v
	}

	volumes := []corev1.Volume{
		{Name: "work", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		{Name: "reports", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
	}
	if cfg.VDBClaim != "" {
		volumes = append(volumes, corev1.Volume{
			Name: "vdb",
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: cfg.VDBClaim},
			},
		})
	} else {
		volumes = append(volumes, corev1.Volume{
			Name:         "vdb",
			VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
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
		Name:            "fetch-image",
		Image:           craneImage,
		Command:         []string{"/ko-app/crane", "pull", "--platform", platform, cfg.Image, imageTar},
		Env:             craneEnv,
		VolumeMounts:    craneMounts,
		ImagePullPolicy: corev1.PullIfNotPresent,
	}}

	script := fmt.Sprintf(`set -e
mkdir -p %[1]s
echo "[depscan-operator] scanning image: %[2]s (from local archive)"
depscan --src %[7]s -o %[1]s -t docker --csaf --no-banner --no-vuln-table || echo "[depscan-operator] depscan exited non-zero"
echo "%[3]s"
cat %[1]s/*.vdr.json 2>/dev/null || echo '{}'
echo ""
echo "%[4]s"
echo "%[5]s"
cat %[1]s/*.csaf.json 2>/dev/null || echo '{}'
echo ""
echo "%[6]s"
`, reportsDir, cfg.Image, VDRBegin, VDREnd, CSAFBegin, CSAFEnd, imageTar)

	depscanContainer := corev1.Container{
		Name:    "depscan",
		Image:   cfg.ScannerImage,
		Command: []string{"/bin/sh", "-c", script},
		Env: []corev1.EnvVar{
			{Name: "VDB_HOME", Value: vdbHome},
			{Name: "DEPSCAN_NO_BANNER", Value: "true"},
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: "work", MountPath: workDir},
			{Name: "reports", MountPath: reportsDir},
			{Name: "vdb", MountPath: vdbHome},
		},
		ImagePullPolicy: corev1.PullIfNotPresent,
		SecurityContext: hardenedContainerSecurityContext(),
	}
	if res := buildResources(cfg.Resources); res != nil {
		depscanContainer.Resources = *res
	}
	for i := range initContainers {
		initContainers[i].SecurityContext = hardenedContainerSecurityContext()
	}

	backoff := int32(1)
	ttl := cfg.TTLSeconds
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: cfg.Namespace,
			Labels:    labels,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            &backoff,
			TTLSecondsAfterFinished: &ttl,
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
	for k, v := range r.Requests {
		if q, err := resource.ParseQuantity(v); err == nil {
			out.Requests[corev1.ResourceName(k)] = q
		}
	}
	for k, v := range r.Limits {
		if q, err := resource.ParseQuantity(v); err == nil {
			out.Limits[corev1.ResourceName(k)] = q
		}
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
