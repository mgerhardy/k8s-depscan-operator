package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DepScanConfigSpec configures operator-wide scan behavior. A single
// cluster-scoped object (conventionally named "default") drives the operator.
type DepScanConfigSpec struct {
	// ScannerImage is the dep-scan container image to run.
	// +kubebuilder:default="ghcr.io/owasp-dep-scan/dep-scan:latest"
	ScannerImage string `json:"scannerImage,omitempty"`

	// CraneImage is the image used to fetch each target image from its registry
	// before scanning. The default works for public and private registries.
	// +kubebuilder:default="gcr.io/go-containerregistry/crane:latest"
	CraneImage string `json:"craneImage,omitempty"`

	// RescanInterval is how long a report stays valid before the image is
	// rescanned. Expressed as a Go duration string (e.g. "24h").
	// +kubebuilder:default="24h"
	RescanInterval metav1.Duration `json:"rescanInterval,omitempty"`

	// IncludeNamespaces restricts scanning to these namespaces. Empty means
	// all namespaces except those in ExcludeNamespaces.
	// +optional
	IncludeNamespaces []string `json:"includeNamespaces,omitempty"`

	// ExcludeNamespaces are never scanned. The operator's own namespace and
	// kube-system are good candidates.
	// +optional
	ExcludeNamespaces []string `json:"excludeNamespaces,omitempty"`

	// JobNamespace is where scan Jobs are created. Defaults to the operator
	// namespace when empty.
	// +optional
	JobNamespace string `json:"jobNamespace,omitempty"`

	// JobTTLSeconds is the TTL applied to finished scan Jobs.
	// +kubebuilder:default=600
	JobTTLSeconds int32 `json:"jobTTLSeconds,omitempty"`

	// MaxConcurrentScans caps how many scan Jobs run at once, bounding the
	// number of heavy scan pods a burst of new images can create. 0 uses the
	// default.
	// +kubebuilder:default=5
	MaxConcurrentScans int32 `json:"maxConcurrentScans,omitempty"`

	// VDBCache configures persistence of the dep-scan vulnerability database
	// to speed up subsequent scans.
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
	Enabled bool `json:"enabled,omitempty"`
	// ClaimName is an existing PVC to mount at VDB_HOME. If empty and Enabled
	// is true, the operator provisions one.
	// +optional
	ClaimName string `json:"claimName,omitempty"`
	// Size is the requested size when the operator provisions the PVC.
	// +kubebuilder:default="10Gi"
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
}

// ResourceRequirements is a trimmed-down resource spec for scan Jobs.
type ResourceRequirements struct {
	// +optional
	Requests map[string]string `json:"requests,omitempty"`
	// +optional
	Limits map[string]string `json:"limits,omitempty"`
}

// DefectDojoSpec configures export to a DefectDojo instance via the
// reimport-scan API, matching the reference .ci/defectdojo.py behavior.
type DefectDojoSpec struct {
	// Enabled gates all DefectDojo export.
	Enabled bool `json:"enabled"`

	// URL is the DefectDojo base URL.
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
// +kubebuilder:printcolumn:name="Scanner",type=string,JSONPath=`.spec.scannerImage`
// +kubebuilder:printcolumn:name="DefectDojo",type=boolean,JSONPath=`.spec.defectDojo.enabled`

// DepScanConfig is the Schema for the cluster-wide operator configuration.
type DepScanConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec DepScanConfigSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// DepScanConfigList contains a list of DepScanConfig.
type DepScanConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DepScanConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&DepScanConfig{}, &DepScanConfigList{})
}
