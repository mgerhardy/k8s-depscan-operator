package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Severity levels mirror the CycloneDX/dep-scan rating vocabulary.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityNone     Severity = "NONE"
	SeverityUnknown  Severity = "UNKNOWN"
)

// Reachability captures the dep-scan reachability verdict for a vulnerable
// package. dep-scan marks a package Reachable when its code is on an executed
// path, otherwise it is only present in the BOM.
type Reachability string

const (
	ReachabilityReachable    Reachability = "reachable"
	ReachabilityNotReachable Reachability = "not-reachable"
	ReachabilityUnknown      Reachability = "unknown"
)

// Labels and annotations used by the operator to correlate reports with the
// images and workloads they describe.
const (
	// LabelImageDigest is the sha256 digest (hex, no prefix) of the scanned image.
	LabelImageDigest = "depscan.io/image-digest"
	// LabelManagedBy marks resources created by this operator.
	LabelManagedBy = "app.kubernetes.io/managed-by"
	// ManagedByValue is the value for LabelManagedBy.
	ManagedByValue = "k8s-depscan-operator"
	// AnnotationImage is the full image reference that was scanned.
	AnnotationImage = "depscan.io/image"
)

// Vulnerability is a single finding reported by dep-scan.
type Vulnerability struct {
	// VulnerabilityID is the CVE/GHSA/advisory identifier.
	VulnerabilityID string `json:"vulnerabilityID"`
	// Resource is the affected package name.
	Resource string `json:"resource,omitempty"`
	// InstalledVersion is the version present in the image.
	InstalledVersion string `json:"installedVersion,omitempty"`
	// FixedVersion is the version that resolves the finding, if known.
	FixedVersion string `json:"fixedVersion,omitempty"`
	// PURL is the package URL of the affected component.
	PURL string `json:"purl,omitempty"`
	// Severity is the normalized severity rating.
	Severity Severity `json:"severity"`
	// Score is the CVSS base score as a string, when available (e.g. "9.8").
	// Stored as a string to keep the CRD portable across languages.
	// +optional
	Score string `json:"score,omitempty"`
	// Title is a short summary of the vulnerability.
	Title string `json:"title,omitempty"`
	// PrimaryLink points to the primary advisory.
	PrimaryLink string `json:"primaryLink,omitempty"`
	// Reachability is the dep-scan reachability verdict.
	// +optional
	Reachability Reachability `json:"reachability,omitempty"`
}

// VulnerabilitySummary aggregates finding counts by severity, plus a
// reachable count so per-namespace queries can prioritize at a glance.
type VulnerabilitySummary struct {
	CriticalCount int `json:"criticalCount"`
	HighCount     int `json:"highCount"`
	MediumCount   int `json:"mediumCount"`
	LowCount      int `json:"lowCount"`
	NoneCount     int `json:"noneCount"`
	UnknownCount  int `json:"unknownCount"`
	// ReachableCount is the number of findings dep-scan marked reachable.
	ReachableCount int `json:"reachableCount"`
}

// ScanPhase describes where a report is in its lifecycle.
type ScanPhase string

const (
	PhasePending   ScanPhase = "Pending"
	PhaseScanning  ScanPhase = "Scanning"
	PhaseCompleted ScanPhase = "Completed"
	PhaseFailed    ScanPhase = "Failed"
)

// DepScanReportSpec identifies what was scanned.
type DepScanReportSpec struct {
	// Image is the full image reference (repo:tag or repo@sha256:...).
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9._:/@-]+$`
	Image string `json:"image"`
	// Workloads lists the workloads in this namespace that use the image.
	// +optional
	Workloads []WorkloadRef `json:"workloads,omitempty"`
	// ImagePullSecrets are the names of docker-registry Secrets, in this
	// report's namespace, that hold credentials for the image's registry.
	// They are collected from the workloads using the image so the scan can
	// pull from private registries in a cluster-agnostic way.
	// +optional
	ImagePullSecrets []string `json:"imagePullSecrets,omitempty"`
}

// WorkloadRef references a workload that runs the scanned image.
type WorkloadRef struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Container string `json:"container,omitempty"`
}

// DepScanReportStatus holds the scan outcome.
type DepScanReportStatus struct {
	// Phase is the current lifecycle phase.
	Phase ScanPhase `json:"phase,omitempty"`
	// Scanner records the dep-scan version/image used.
	Scanner string `json:"scanner,omitempty"`
	// UpdateTimestamp is when the report was last updated.
	// +optional
	UpdateTimestamp *metav1.Time `json:"updateTimestamp,omitempty"`
	// Summary aggregates findings by severity.
	Summary VulnerabilitySummary `json:"summary,omitempty"`
	// Vulnerabilities is the full list of findings.
	// +optional
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	// ScanJob is the name of the Job that produced this report.
	ScanJob string `json:"scanJob,omitempty"`
	// Message carries error or status detail.
	Message string `json:"message,omitempty"`
	// Exported indicates whether this report was pushed to DefectDojo.
	Exported bool `json:"exported,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=dsr;depscanreport
// +kubebuilder:printcolumn:name="Image",type=string,JSONPath=`.spec.image`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Critical",type=integer,JSONPath=`.status.summary.criticalCount`
// +kubebuilder:printcolumn:name="High",type=integer,JSONPath=`.status.summary.highCount`
// +kubebuilder:printcolumn:name="Reachable",type=integer,JSONPath=`.status.summary.reachableCount`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// DepScanReport holds the scan results for one (namespace, image) pair, so
// findings can be queried per namespace.
type DepScanReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DepScanReportSpec   `json:"spec,omitempty"`
	Status DepScanReportStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// DepScanReportList contains a list of DepScanReport.
type DepScanReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DepScanReport `json:"items"`
}

func init() {
	SchemeBuilder.Register(&DepScanReport{}, &DepScanReportList{})
}
