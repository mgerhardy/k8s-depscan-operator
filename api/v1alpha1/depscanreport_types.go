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
	// LabelImageDigest holds a short hash (16 hex chars) of the image
	// *reference* string, used to select a report's objects. Despite the key
	// name it is not the registry manifest digest; enable scanByDigest to
	// scan (and key reports) by the running digest.
	LabelImageDigest = "depscan.io/image-digest"
	// LabelManagedBy marks resources created by this operator.
	LabelManagedBy = "app.kubernetes.io/managed-by"
	// ManagedByValue is the value for LabelManagedBy.
	ManagedByValue = "k8s-depscan-operator"
	// AnnotationImage is the full image reference that was scanned.
	AnnotationImage = "depscan.io/image"
	// LabelVDBVersion records which VDB version a scan Job consumes, so the
	// cache GC never deletes a version still in use.
	LabelVDBVersion = "depscan.io/vdb-version"
	// LabelComponent distinguishes operator-created Job kinds (e.g. the VDB
	// prime Job from scan Jobs).
	LabelComponent = "depscan.io/component"
	// ComponentVDBPrime marks the VDB prime Job.
	ComponentVDBPrime = "vdb-prime"
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
// reachable count so per-namespace queries can prioritize at a glance. The
// severity counts partition all findings: every finding falls into exactly one
// of critical/high/medium/low/none/unknown, so they sum to the total.
//
// Every count is optional in the schema (but always written by the operator):
// fields were added over time, and a required field that an older object
// lacks makes every merge patch on that object fail validation.
type VulnerabilitySummary struct {
	// TotalCount is the number of findings.
	// +optional
	TotalCount int `json:"totalCount"`
	// CriticalCount is the number of findings rated critical severity.
	// +optional
	CriticalCount int `json:"criticalCount"`
	// HighCount is the number of findings rated high severity.
	// +optional
	HighCount int `json:"highCount"`
	// MediumCount is the number of findings rated medium (or moderate) severity.
	// +optional
	MediumCount int `json:"mediumCount"`
	// LowCount is the number of findings rated low severity.
	// +optional
	LowCount int `json:"lowCount"`
	// NoneCount is the number of findings rated none/informational (no
	// meaningful severity, e.g. CVSS 0).
	// +optional
	NoneCount int `json:"noneCount"`
	// UnknownCount is the number of findings whose severity could not be
	// determined (missing or unrecognized rating). It is unrelated to per-CVE
	// reachability being unknown.
	// +optional
	UnknownCount int `json:"unknownCount"`
	// ReachableCount is the number of findings dep-scan marked reachable,
	// across all severities (so it can exceed CriticalCount+HighCount).
	// +optional
	ReachableCount int `json:"reachableCount"`
	// ReachableCriticalCount is the number of critical findings marked
	// reachable: the first ones to fix.
	// +optional
	ReachableCriticalCount int `json:"reachableCriticalCount"`
	// ReachableHighCount is the number of high findings marked reachable.
	// +optional
	ReachableHighCount int `json:"reachableHighCount"`
	// NotReachableCount is the number of findings dep-scan analyzed and found
	// not reachable (vulnerable code is present but not on an execute path).
	// +optional
	NotReachableCount int `json:"notReachableCount"`
	// UnknownReachabilityCount is the number of findings with no reachability
	// data (reachability analysis did not cover them, e.g. OS/distro packages).
	// +optional
	UnknownReachabilityCount int `json:"unknownReachabilityCount"`
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
	// Platform is the os/arch (e.g. "linux/arm64") of the node the image was
	// first seen running on; the scan pulls that variant of a multi-arch
	// image. Empty means linux/amd64 unless the config sets a platform.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]+/[a-z0-9]+(/[a-z0-9]+)?$`
	// +optional
	Platform string `json:"platform,omitempty"`
}

// WorkloadRef references a workload that runs the scanned image.
type WorkloadRef struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Container string `json:"container,omitempty"`
}

// Exposure is how network-reachable the workload running an image is. It is the
// strongest signal for whether an image CVE is actually exploitable: a
// cluster-internal service pushes most base-image CVEs out of reach.
type Exposure string

const (
	ExposureInternet        Exposure = "internet"         // public (or unknown) LoadBalancer/Ingress/Gateway address
	ExposureNetworkAdjacent Exposure = "network-adjacent" // private LB/Ingress/Gateway, or NodePort
	ExposureClusterInternal Exposure = "cluster-internal" // ClusterIP only
	ExposureNotAService     Exposure = "not-a-service"    // init container / no Service
)

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
	// ReachabilityAnalyzed is true when dep-scan ran reachability analysis for
	// this image. When false, the reachability counts are "not analyzed" rather
	// than "none reachable": a zero ReachableCount with ReachabilityAnalyzed
	// false means reachability was never determined (e.g. OS-only images), not
	// that the image is free of reachable findings.
	// +optional
	ReachabilityAnalyzed bool `json:"reachabilityAnalyzed,omitempty"`
	// Vulnerabilities is the full list of findings.
	// +optional
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	// Exposure is the network reachability tier of the workloads running this
	// image, computed from Services and Ingresses.
	// +optional
	Exposure Exposure `json:"exposure,omitempty"`
	// ExposureEvidence briefly explains how Exposure was determined.
	// +optional
	ExposureEvidence string `json:"exposureEvidence,omitempty"`
	// ScanJob is the name of the Job that produced this report.
	ScanJob string `json:"scanJob,omitempty"`
	// Message carries error or status detail.
	Message string `json:"message,omitempty"`
	// Exported indicates whether this report was pushed to DefectDojo.
	Exported bool `json:"exported,omitempty"`
	// ConsecutiveFailures counts failed scans since the last successful one;
	// it drives the retry backoff.
	// +optional
	ConsecutiveFailures int32 `json:"consecutiveFailures,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=dsr;depscanreport
// +kubebuilder:printcolumn:name="Image",type=string,JSONPath=`.spec.image`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Total",type=integer,JSONPath=`.status.summary.totalCount`
// +kubebuilder:printcolumn:name="Critical",type=integer,JSONPath=`.status.summary.criticalCount`
// +kubebuilder:printcolumn:name="High",type=integer,JSONPath=`.status.summary.highCount`
// +kubebuilder:printcolumn:name="Medium",type=integer,JSONPath=`.status.summary.mediumCount`,priority=1
// +kubebuilder:printcolumn:name="Low",type=integer,JSONPath=`.status.summary.lowCount`,priority=1
// +kubebuilder:printcolumn:name="Reach Crit",type=integer,JSONPath=`.status.summary.reachableCriticalCount`,description="Critical findings marked reachable"
// +kubebuilder:printcolumn:name="Reach High",type=integer,JSONPath=`.status.summary.reachableHighCount`,description="High findings marked reachable"
// +kubebuilder:printcolumn:name="Reachable",type=integer,JSONPath=`.status.summary.reachableCount`,description="Findings marked reachable, all severities"
// +kubebuilder:printcolumn:name="Exposure",type=string,JSONPath=`.status.exposure`
// +kubebuilder:printcolumn:name="Last Scan",type=date,JSONPath=`.status.updateTimestamp`
// +kubebuilder:printcolumn:name="Message",type=string,JSONPath=`.status.message`,priority=1

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
	register(&DepScanReport{}, &DepScanReportList{})
}
