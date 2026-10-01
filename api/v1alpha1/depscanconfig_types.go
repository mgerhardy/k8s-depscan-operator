package v1alpha1

import (
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DefaultVDBCacheSize suits the full "app+os" database (~70 GB extracted plus
// the compressed artifact and extraction headroom).
const DefaultVDBCacheSize = "100Gi"

// Default images, pinned by digest so every node runs the same, reviewed
// scanner. Keep these in sync with the kubebuilder:default markers below
// (Dependabot does not see them; bump both together).
const (
	DefaultScannerImage = "ghcr.io/owasp-dep-scan/dep-scan:v6.3.0@sha256:c305f241a3c2e35a90472ef7cb971b03904f719a6b736ab40b4a0039ce8470c4"
	DefaultCraneImage   = "gcr.io/go-containerregistry/crane:v0.22.1@sha256:1f968817b95790bed063f71175aa6b8ff879fa17064020415f3e18bb6e6a36e1"
)

// DepScanConfigSpec configures operator-wide scan behavior. A single
// cluster-scoped object (conventionally named "default") drives the operator.
type DepScanConfigSpec struct {
	// ScannerImage is the dep-scan container image to run.
	// +kubebuilder:default="ghcr.io/owasp-dep-scan/dep-scan:v6.3.0@sha256:c305f241a3c2e35a90472ef7cb971b03904f719a6b736ab40b4a0039ce8470c4"
	ScannerImage string `json:"scannerImage,omitempty"`

	// CraneImage is the image used to fetch each target image from its registry
	// before scanning. The default works for public and private registries.
	// +kubebuilder:default="gcr.io/go-containerregistry/crane:v0.22.1@sha256:1f968817b95790bed063f71175aa6b8ff879fa17064020415f3e18bb6e6a36e1"
	CraneImage string `json:"craneImage,omitempty"`

	// ScanProfile is dep-scan's analysis profile (its --profile value).
	// "research" enables reachability analysis; "generic" is a faster scan
	// without it. See dep-scan docs for the full list.
	// +kubebuilder:validation:Enum=research;generic;appsec;operational;threat-modeling;license-compliance
	// +kubebuilder:default=research
	ScanProfile string `json:"scanProfile,omitempty"`

	// RescanInterval is how long a report stays valid before the image is
	// rescanned. Expressed as a Go duration string (e.g. "24h").
	// +kubebuilder:default="24h"
	// +kubebuilder:validation:XValidation:rule="self.matches('^([0-9]+([.][0-9]+)?(ns|us|µs|ms|s|m|h))+$')",message="must be a Go duration such as 24h, 90m or 30s"
	RescanInterval metav1.Duration `json:"rescanInterval,omitempty"`

	// IncludeNamespaces restricts scanning to these namespaces. Empty means
	// all namespaces except those in ExcludeNamespaces. Entries may be
	// shell-style globs (e.g. "team-*", "*-prod"); an entry without glob
	// characters is matched exactly.
	// +optional
	IncludeNamespaces []string `json:"includeNamespaces,omitempty"`

	// ExcludeNamespaces are never scanned, taking precedence over
	// IncludeNamespaces. The operator's own namespace and kube-system are good
	// candidates. Entries may be shell-style globs (e.g. "*-system"); an entry
	// without glob characters is matched exactly.
	// +optional
	ExcludeNamespaces []string `json:"excludeNamespaces,omitempty"`

	// JobNamespace is where scan Jobs are created. Defaults to the operator
	// namespace when empty.
	// +optional
	JobNamespace string `json:"jobNamespace,omitempty"`

	// JobTTLSeconds is the TTL applied to finished scan Jobs.
	// +kubebuilder:default=600
	// +kubebuilder:validation:Minimum=0
	JobTTLSeconds int32 `json:"jobTTLSeconds,omitempty"`

	// MaxConcurrentScans caps how many scan Jobs run at once, bounding the
	// number of heavy scan pods a burst of new images can create. 0 uses the
	// default.
	// +kubebuilder:default=5
	// +kubebuilder:validation:Minimum=0
	MaxConcurrentScans int32 `json:"maxConcurrentScans,omitempty"`

	// ScanByDigest scans the image digest a container actually runs (from the
	// pod status) instead of the tag in the pod spec, so a moved tag (e.g.
	// ":latest") cannot make a report describe a different image than the one
	// running. Reports are then keyed by digest: each new digest gets a fresh
	// report and the old one is pruned. Off by default because some registries
	// (e.g. certain Artifactory repositories) do not serve manifests by digest.
	// +optional
	ScanByDigest bool `json:"scanByDigest,omitempty"`

	// Platform forces the os/arch (e.g. "linux/amd64") pulled for every scan.
	// Empty (the default) scans the variant matching the node each image runs
	// on, so arm64 nodes get arm64 scans.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]+/[a-z0-9]+(/[a-z0-9]+)?$`
	// +optional
	Platform string `json:"platform,omitempty"`

	// ScanTimeout bounds how long a scan Job may run before it is failed
	// (activeDeadlineSeconds). It keeps a hanging or pathological image from
	// holding a MaxConcurrentScans slot indefinitely. A Go duration string.
	// +kubebuilder:default="1h"
	// +kubebuilder:validation:XValidation:rule="self.matches('^([0-9]+([.][0-9]+)?(ns|us|µs|ms|s|m|h))+$')",message="must be a Go duration such as 24h, 90m or 30s"
	ScanTimeout metav1.Duration `json:"scanTimeout,omitempty"`

	// ScanWorkSizeLimit caps the scratch volume holding the pulled image
	// archive (an emptyDir sizeLimit). A scan pod exceeding it is evicted
	// instead of filling the node's disk.
	// +kubebuilder:default="20Gi"
	// +kubebuilder:validation:Pattern=`^(([0-9]+([.][0-9]*)?)|([.][0-9]+))(([KMGTPE]i)|[numkMGTPE]|([eE][-+]?(([0-9]+([.][0-9]*)?)|([.][0-9]+))))?$`
	ScanWorkSizeLimit string `json:"scanWorkSizeLimit,omitempty"`

	// VDBCache configures persistence of the dep-scan vulnerability database
	// to speed up subsequent scans. Enabled by default: without it every scan
	// downloads the full (tens of GB) database into node-local scratch space.
	// Set enabled: false to opt out.
	// +kubebuilder:default={enabled: true}
	// +optional
	VDBCache *VDBCacheSpec `json:"vdbCache,omitempty"`

	// Resources are the resource requirements applied to scan Jobs.
	// +optional
	Resources *ResourceRequirements `json:"resources,omitempty"`

	// DefectDojo enables and configures export of CSAF VEX reports.
	// +optional
	DefectDojo *DefectDojoSpec `json:"defectDojo,omitempty"`
}

// VDBCacheSpec controls the vulnerability-database cache volume.
type VDBCacheSpec struct {
	// Enabled turns on PVC-backed caching of the VDB across scan Jobs.
	// +kubebuilder:default=true
	// +optional
	Enabled bool `json:"enabled"`
	// ClaimName is an existing PVC to mount at VDB_HOME. If empty and Enabled
	// is true, the operator provisions one.
	// +optional
	ClaimName string `json:"claimName,omitempty"`
	// Size is the requested size when the operator provisions the PVC. The
	// default suits the full "app+os" database, which is roughly 70 GB
	// extracted plus the compressed artifact and extraction headroom. With
	// Scope "app" a much smaller cache (around 5Gi) is enough.
	// +kubebuilder:default="100Gi"
	// +kubebuilder:validation:Pattern=`^(([0-9]+([.][0-9]*)?)|([.][0-9]+))(([KMGTPE]i)|[numkMGTPE]|([eE][-+]?(([0-9]+([.][0-9]*)?)|([.][0-9]+))))?$`
	Size string `json:"size,omitempty"`
	// StorageClassName optionally pins the PVC storage class.
	// +optional
	StorageClassName string `json:"storageClassName,omitempty"`
	// AccessMode is the PVC access mode for a provisioned cache. Use
	// ReadWriteMany on multi-node clusters (e.g. with an EFS/NFS storage class)
	// so scan pods on different nodes can share one cache; ReadWriteOnce only
	// works when all scan pods land on a single node.
	// +kubebuilder:validation:Enum=ReadWriteOnce;ReadWriteMany
	// +kubebuilder:default=ReadWriteOnce
	AccessMode string `json:"accessMode,omitempty"`
	// RefreshInterval is how often the operator re-primes the VDB to a new
	// version. A Go duration string (e.g. "24h").
	// +kubebuilder:default="24h"
	// +kubebuilder:validation:XValidation:rule="self.matches('^([0-9]+([.][0-9]+)?(ns|us|µs|ms|s|m|h))+$')",message="must be a Go duration such as 24h, 90m or 30s"
	RefreshInterval metav1.Duration `json:"refreshInterval,omitempty"`
	// DownloadURL overrides where the prime Job fetches the vulnerability
	// database from. It is an OCI image reference (e.g.
	// "registry.example.com/vdb/vdbxz:v6.7") passed to dep-scan as the
	// VDB_DATABASE_URL environment variable. Use this to pull from an internal
	// mirror in air-gapped or egress-restricted clusters. Empty uses dep-scan's
	// built-in default source.
	// +optional
	DownloadURL string `json:"downloadURL,omitempty"`
	// Scope selects how much of the vulnerability database to download.
	// "app+os" (the default) is the full database covering application and OS
	// distro packages; it is large (tens of GB extracted), so size the cache
	// accordingly. "app" downloads only application-ecosystem vulnerabilities,
	// a much smaller database, at the cost of not flagging OS/distro package
	// CVEs. Use "app" when your scan targets are application images without
	// meaningful OS layers, or to keep the cache small.
	// +kubebuilder:validation:Enum=app;app+os
	// +kubebuilder:default=app+os
	Scope string `json:"scope,omitempty"`
	// PrimeTimeout bounds how long a VDB prime Job may run. A Go duration
	// string.
	// +kubebuilder:default="4h"
	// +kubebuilder:validation:XValidation:rule="self.matches('^([0-9]+([.][0-9]+)?(ns|us|µs|ms|s|m|h))+$')",message="must be a Go duration such as 24h, 90m or 30s"
	PrimeTimeout metav1.Duration `json:"primeTimeout,omitempty"`
}

// ResourceRequirements is a trimmed-down resource spec for scan Jobs.
type ResourceRequirements struct {
	// Values are Kubernetes quantities (e.g. "500m", "2Gi"), validated by the
	// API server's built-in quantity schema.
	// +optional
	// +kubebuilder:validation:MaxProperties=3
	// +kubebuilder:validation:XValidation:rule="self.all(k, k in ['cpu', 'memory', 'ephemeral-storage'])",message="only cpu, memory and ephemeral-storage are supported"
	Requests map[string]resource.Quantity `json:"requests,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxProperties=3
	// +kubebuilder:validation:XValidation:rule="self.all(k, k in ['cpu', 'memory', 'ephemeral-storage'])",message="only cpu, memory and ephemeral-storage are supported"
	Limits map[string]resource.Quantity `json:"limits,omitempty"`
}

// DefectDojoSpec configures export to a DefectDojo instance via the
// reimport-scan API, matching the reference .ci/defectdojo.py behavior.
type DefectDojoSpec struct {
	// Enabled gates all DefectDojo export.
	Enabled bool `json:"enabled"`

	// URL is the DefectDojo base URL.
	// +kubebuilder:validation:Pattern=`^https?://[^\s/]+`
	URL string `json:"url"`

	// ScanType is the DefectDojo scan type for the uploaded report.
	// +kubebuilder:default="CSAF Scan"
	ScanType string `json:"scanType,omitempty"`

	// ProductType is the product type used for auto-created products.
	// +kubebuilder:default="Research and Development"
	ProductType string `json:"productType,omitempty"`

	// EngagementName is the engagement used for all uploads.
	// +kubebuilder:default="Cluster Dep-Scan Reachability Analysis"
	EngagementName string `json:"engagementName,omitempty"`

	// ProductNameTemplate builds the DefectDojo product name. Supports the
	// placeholders {namespace} and {image}. Defaults to "{namespace}".
	// +kubebuilder:default="{namespace}"
	ProductNameTemplate string `json:"productNameTemplate,omitempty"`

	// CredentialsSecret references a Secret holding DefectDojo credentials.
	// Expected keys: "username" (optional, default admin), "password".
	CredentialsSecret SecretRef `json:"credentialsSecret"`

	// CloseOldFindings maps to the reimport-scan close_old_findings flag.
	// +kubebuilder:default=true
	CloseOldFindings bool `json:"closeOldFindings,omitempty"`

	// AllowInsecureURL permits a plain http:// DefectDojo URL. Off by default
	// so credentials are not sent in cleartext by misconfiguration.
	// +optional
	AllowInsecureURL bool `json:"allowInsecureURL,omitempty"`
}

// SecretRef references a key within a Secret.
type SecretRef struct {
	Name string `json:"name"`
	// Namespace defaults to the operator namespace when empty.
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=dsc
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Valid",type=string,JSONPath=`.status.conditions[?(@.type=="ConfigValid")].status`
// +kubebuilder:printcolumn:name="VDB Ready",type=string,JSONPath=`.status.conditions[?(@.type=="VDBReady")].status`
// +kubebuilder:printcolumn:name="VDB Version",type=string,JSONPath=`.status.vdb.version`
// +kubebuilder:printcolumn:name="Scanner",type=string,JSONPath=`.spec.scannerImage`,priority=1
// +kubebuilder:printcolumn:name="DefectDojo",type=boolean,JSONPath=`.spec.defectDojo.enabled`,priority=1
// The operator reads exactly one config, named "default"; reject any other
// name instead of silently ignoring it.
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'default'",message="the operator only reads the DepScanConfig named 'default'"

// DepScanConfig is the Schema for the cluster-wide operator configuration.
type DepScanConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec DepScanConfigSpec `json:"spec,omitempty"`
	// +optional
	Status DepScanConfigStatus `json:"status,omitempty"`
}

// Condition types reported on DepScanConfig.
const (
	// ConditionConfigValid is True when the operator could apply the spec.
	ConditionConfigValid = "ConfigValid"
	// ConditionVDBReady is True when a vulnerability database version is
	// available to scans (or the cache is disabled).
	ConditionVDBReady = "VDBReady"
)

// DepScanConfigStatus reports how the operator applies the config and the
// state of the shared vulnerability database.
type DepScanConfigStatus struct {
	// ObservedGeneration is the spec generation the status describes.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// Conditions: ConfigValid and VDBReady.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// VDB describes the shared vulnerability database cache.
	// +optional
	VDB *VDBStatus `json:"vdb,omitempty"`
}

// VDBStatus is the state of the shared vulnerability database cache.
type VDBStatus struct {
	// Version is the database version scans currently use.
	// +optional
	Version string `json:"version,omitempty"`
	// PrimedAt is when that version was last downloaded or confirmed.
	// +optional
	PrimedAt *metav1.Time `json:"primedAt,omitempty"`
	// ConsecutiveFailures counts failed prime attempts since the last success.
	// +optional
	ConsecutiveFailures int32 `json:"consecutiveFailures,omitempty"`
	// LastError explains the most recent failed prime.
	// +optional
	LastError string `json:"lastError,omitempty"`
	// NextRetry is when the next prime is attempted after a failure.
	// +optional
	NextRetry *metav1.Time `json:"nextRetry,omitempty"`
}

// +kubebuilder:object:root=true

// DepScanConfigList contains a list of DepScanConfig.
type DepScanConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DepScanConfig `json:"items"`
}

func init() {
	register(&DepScanConfig{}, &DepScanConfigList{})
}
