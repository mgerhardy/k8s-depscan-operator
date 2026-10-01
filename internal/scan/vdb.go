package scan

import (
	"fmt"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
)

const (
	// vdbRoot is where the shared VDB cache PVC is mounted. Each VDB version
	// lives in a subdirectory; latest.meta names the current one.
	vdbRoot      = "/vdbcache"
	vdbLatestPtr = "/vdbcache/latest.meta"
	// VDBPrimeJobName is the fixed name of the VDB prime Job.
	VDBPrimeJobName = "depscan-vdb-prime"
	// VDBGCJobName is the fixed name of the VDB garbage-collection Job.
	VDBGCJobName = "depscan-vdb-gc"
	// PrimeContainerName is the prime Job's container; its termination
	// message carries the published version key.
	PrimeContainerName = "vdb-prime"
)

// PrimeJobConfig describes the VDB prime Job.
type PrimeJobConfig struct {
	ScannerImage string
	Namespace    string
	VDBClaim     string
	TTLSeconds   int32
	Resources    *depscanv1alpha1.ResourceRequirements
	// DownloadURL optionally overrides the VDB source. When set it is injected
	// as the VDB_DATABASE_URL env var so dep-scan fetches from an internal
	// mirror instead of its default registry.
	DownloadURL string
	// Scope selects the database scope passed to depscan-vdb download via
	// --scope ("app" or "app+os"). Empty uses the dep-scan default (app+os).
	Scope string
	// Force skips reusing the version named by latest.meta and always
	// downloads. The operator sets it for a due refresh; without it a prime
	// (e.g. after an operator restart) reuses an intact cached version.
	Force bool
	// Timeout sets the Job's activeDeadlineSeconds; zero means no deadline.
	Timeout time.Duration
}

// BuildPrimeJob builds a Job that downloads the dep-scan VDB into a temp dir,
// derives a version key from the DB's own metadata (schema + variant +
// freshness timestamp), atomically moves it to /vdbcache/<key>, and writes the
// key to /vdbcache/latest.meta. It is a no-op when that version already exists.
//
// dep-scan does not expose a single incrementing DB version: vdb.meta records a
// creation timestamp, the .depscan-vdb-image marker records the variant, and
// the image tag carries the schema (e.g. v6.7.x). The key is composed from all
// three so identical data maps to the same directory (no churn) while a genuine
// refresh rolls over to a new one.
func BuildPrimeJob(cfg PrimeJobConfig) *batchv1.Job {
	labels := map[string]string{
		depscanv1alpha1.LabelManagedBy: depscanv1alpha1.ManagedByValue,
		depscanv1alpha1.LabelComponent: depscanv1alpha1.ComponentVDBPrime,
	}

	// Build the download command, optionally pinning the database scope.
	downloadCmd := "depscan-vdb download"
	if cfg.Scope != "" {
		downloadCmd += " --scope " + cfg.Scope
	}

	// Reuse an already-cached version instead of re-downloading: if latest.meta
	// names an intact version directory, republish the pointer and exit. A
	// refresh sets Force, which omits this short-circuit.
	reuseBlock := ""
	if !cfg.Force {
		reuseBlock = fmt.Sprintf(`cur=$(cat "%[2]s" 2>/dev/null || true)
if [ -n "$cur" ] && [ -f "%[1]s/$cur/vdb.meta" ]; then
  echo "[vdb-prime] reusing cached version $cur (no download needed)"
  echo "[vdb-prime] latest.meta -> $cur"
  printf '%%s' "$cur" > /dev/termination-log
  exit 0
fi
`, vdbRoot, vdbLatestPtr)
	}

	// Download into a private temp VDB_HOME, read the metadata dep-scan wrote,
	// compose a filesystem-safe key, then atomically publish it. The download
	// runs in the background while a watcher prints the cache size every 30s so
	// users can gauge progress on the multi-GB pull.
	script := fmt.Sprintf(`set -e
%[4]sTMP="%[1]s/.tmp-$$-$(date +%%s)"
mkdir -p "$TMP"
export VDB_HOME="$TMP"
echo "[vdb-prime] downloading VDB into $TMP"
%[3]s &
dl=$!
# Progress watcher: report how much has landed until the download exits.
while kill -0 "$dl" 2>/dev/null; do
  sleep 30
  kill -0 "$dl" 2>/dev/null || break
  sz=$(du -sh "$TMP" 2>/dev/null | cut -f1)
  echo "[vdb-prime] downloading... ${sz:-0} fetched so far"
done
wait "$dl"
# Derive a version key from the metadata dep-scan writes.
ts=$(grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' "$TMP/vdb.meta" 2>/dev/null | head -1)
variant=$(tr -cd 'A-Za-z0-9._-' < "$TMP/.depscan-vdb-image" 2>/dev/null | sed 's#.*/##; s#[^A-Za-z0-9]#-#g' | head -c 40)
if [ -z "$ts" ] || [ ! -f "$TMP/vdb.meta" ]; then
  echo "[vdb-prime] ERROR: no vdb.meta/version after download" >&2
  rm -rf "$TMP"; exit 1
fi
key="${variant:-vdb}-${ts}"
dst="%[1]s/$key"
if [ -d "$dst" ]; then
  echo "[vdb-prime] version $key already present; refreshing pointer"
  rm -rf "$TMP"
else
  echo "[vdb-prime] publishing version $key (size $(du -sh "$TMP" 2>/dev/null | cut -f1))"
  mv "$TMP" "$dst"            # atomic rename within the same volume
fi
printf '%%s' "$key" > "%[2]s"
echo "[vdb-prime] latest.meta -> $key"
# Report the key via the termination message so the operator can read it from
# the pod status instead of scraping logs.
printf '%%s' "$key" > /dev/termination-log
`, vdbRoot, vdbLatestPtr, downloadCmd, reuseBlock)

	backoff := int32(2)
	ttl := cfg.TTLSeconds
	container := corev1.Container{
		Name:                     PrimeContainerName,
		Image:                    cfg.ScannerImage,
		Command:                  []string{"/bin/sh", "-c", script},
		TerminationMessagePath:   corev1.TerminationMessagePathDefault,
		TerminationMessagePolicy: corev1.TerminationMessageReadFile,
		VolumeMounts:             []corev1.VolumeMount{{Name: "vdb", MountPath: vdbRoot}},
		ImagePullPolicy:          corev1.PullIfNotPresent,
		SecurityContext:          hardenedContainerSecurityContext(),
	}
	if cfg.DownloadURL != "" {
		// Point dep-scan at a mirror instead of its default source.
		container.Env = append(container.Env, corev1.EnvVar{Name: "VDB_DATABASE_URL", Value: cfg.DownloadURL})
	}
	if res := buildResources(cfg.Resources); res != nil {
		container.Resources = *res
	}

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      VDBPrimeJobName,
			Namespace: cfg.Namespace,
			Labels:    labels,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            &backoff,
			ActiveDeadlineSeconds:   deadlineSeconds(cfg.Timeout),
			TTLSecondsAfterFinished: &ttl,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					RestartPolicy:                corev1.RestartPolicyNever,
					AutomountServiceAccountToken: boolPtr(false),
					SecurityContext: &corev1.PodSecurityContext{
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					Containers: []corev1.Container{container},
					Volumes: []corev1.Volume{{
						Name: "vdb",
						VolumeSource: corev1.VolumeSource{
							PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: cfg.VDBClaim},
						},
					}},
				},
			},
		},
	}
}

// gcJobTimeout bounds the GC Job; deleting stale versions is quick.
const gcJobTimeout = 30 * time.Minute

// VDBGCJobConfig describes the VDB garbage-collection Job.
type VDBGCJobConfig struct {
	ScannerImage string
	Namespace    string
	VDBClaim     string
	TTLSeconds   int32
	KeepVersions []string // version dirs to preserve (current + in-use)
}

// BuildVDBGCJob builds a Job that removes stale per-version directories from the
// cache PVC, keeping the listed versions, the version latest.meta names, and
// any in-progress temp dirs. The operator computes KeepVersions (current +
// versions still consumed by active scans); the Job does the filesystem
// deletion the operator cannot.
func BuildVDBGCJob(cfg VDBGCJobConfig) *batchv1.Job {
	labels := map[string]string{
		depscanv1alpha1.LabelManagedBy: depscanv1alpha1.ManagedByValue,
		depscanv1alpha1.LabelComponent: "vdb-gc",
	}

	// Build a newline-separated keep-list the script matches against.
	keep := ""
	for _, v := range cfg.KeepVersions {
		keep += v + "\n"
	}
	script := fmt.Sprintf(`set -e
keep="%[2]s"
cd %[1]s || exit 0
ptr=$(cat latest.meta 2>/dev/null || true)
for d in */; do
  name="${d%%/}"
  case "$name" in
    .tmp-*) continue ;;   # in-progress download, leave alone
  esac
  if [ -n "$ptr" ] && [ "$name" = "$ptr" ]; then
    continue              # published pointer target: always keep
  fi
  if printf '%%s' "$keep" | grep -qxF "$name"; then
    continue              # current or in-use: keep
  fi
  echo "[vdb-gc] removing stale version $name"
  rm -rf "$name"
done
`, vdbRoot, keep)

	backoff := int32(1)
	ttl := cfg.TTLSeconds
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: VDBGCJobName, Namespace: cfg.Namespace, Labels: labels},
		Spec: batchv1.JobSpec{
			BackoffLimit:            &backoff,
			ActiveDeadlineSeconds:   deadlineSeconds(gcJobTimeout),
			TTLSecondsAfterFinished: &ttl,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					RestartPolicy:                corev1.RestartPolicyNever,
					AutomountServiceAccountToken: boolPtr(false),
					SecurityContext: &corev1.PodSecurityContext{
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					Containers: []corev1.Container{{
						Name:            "vdb-gc",
						Image:           cfg.ScannerImage,
						Command:         []string{"/bin/sh", "-c", script},
						VolumeMounts:    []corev1.VolumeMount{{Name: "vdb", MountPath: vdbRoot}},
						ImagePullPolicy: corev1.PullIfNotPresent,
						SecurityContext: hardenedContainerSecurityContext(),
					}},
					Volumes: []corev1.Volume{{
						Name: "vdb",
						VolumeSource: corev1.VolumeSource{
							PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: cfg.VDBClaim},
						},
					}},
				},
			},
		},
	}
}
