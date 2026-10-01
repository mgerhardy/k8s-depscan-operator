package controller

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
)

func TestNamespaceInScope(t *testing.T) {
	cfg := depscanv1alpha1.DepScanConfigSpec{
		ExcludeNamespaces: []string{"kube-system"},
	}
	if namespaceInScope("kube-system", cfg) {
		t.Error("kube-system should be excluded")
	}
	if !namespaceInScope("default", cfg) {
		t.Error("default should be in scope with no include list")
	}

	cfg = depscanv1alpha1.DepScanConfigSpec{
		IncludeNamespaces: []string{"prod"},
	}
	if !namespaceInScope("prod", cfg) {
		t.Error("prod should be in scope")
	}
	if namespaceInScope("default", cfg) {
		t.Error("default should be out of scope when include list is set")
	}

	// Glob patterns are supported in both include and exclude lists.
	cfg = depscanv1alpha1.DepScanConfigSpec{
		IncludeNamespaces: []string{"team-*", "app-?"},
		ExcludeNamespaces: []string{"*-system"},
	}
	for ns, want := range map[string]bool{
		"team-main":   true,  // matches team-*
		"team-local":  true,  // matches team-*
		"app-a":       true,  // matches app-?
		"app-ab":      false, // ? matches a single char only
		"prod":        false, // not in include list
		"team-system": false, // excluded by *-system before include is checked
	} {
		if got := namespaceInScope(ns, cfg); got != want {
			t.Errorf("namespaceInScope(%q) = %v, want %v", ns, got, want)
		}
	}
}

func TestReachabilityMessage(t *testing.T) {
	s := depscanv1alpha1.VulnerabilitySummary{ReachableCount: 18, NotReachableCount: 170, UnknownReachabilityCount: 2}
	if got := reachabilityMessage(190, s, true); got != "190 findings (18 reachable, 170 not-reachable, 2 undetermined)" {
		t.Errorf("analyzed message = %q", got)
	}
	if got := reachabilityMessage(190, depscanv1alpha1.VulnerabilitySummary{}, false); got != "190 findings (reachability not analyzed)" {
		t.Errorf("not-analyzed message = %q", got)
	}
}

func TestResolvedImage(t *testing.T) {
	cases := []struct {
		imageID, want string
	}{
		{"docker-pullable://nginx@sha256:abc", "nginx@sha256:abc"},
		{"nginx@sha256:def", "nginx@sha256:def"},
		{"", ""},
		{"containerd://no-digest", ""},
	}
	for _, c := range cases {
		if got := resolvedImage(c.imageID); got != c.want {
			t.Errorf("resolvedImage(%q) = %q, want %q", c.imageID, got, c.want)
		}
	}
}

func TestHasTagOrDigest(t *testing.T) {
	cases := map[string]bool{
		"nginx:1.25":                      true,
		"repo.example.com:5000/app:1.0":   true,
		"repo.example.com/app@sha256:abc": true,
		"nginx":                           false,
		"repo.example.com:5000/app":       false, // registry port, no tag
	}
	for img, want := range cases {
		if got := hasTagOrDigest(img); got != want {
			t.Errorf("hasTagOrDigest(%q) = %v, want %v", img, got, want)
		}
	}
}

func TestRenderProductName(t *testing.T) {
	if got := renderProductName("{namespace}", "demo", "nginx:latest"); got != "demo" {
		t.Errorf("got %q, want demo", got)
	}
	if got := renderProductName("{namespace}/{image}", "demo", "nginx:latest"); got != "demo/nginx:latest" {
		t.Errorf("got %q", got)
	}
	if got := renderProductName("", "demo", "x"); got != "demo" {
		t.Errorf("empty template should default to namespace, got %q", got)
	}
}

func TestWithDefaults(t *testing.T) {
	spec := withDefaults(depscanv1alpha1.DepScanConfigSpec{})
	if spec.ScannerImage == "" {
		t.Error("scanner image should default")
	}
	if spec.RescanInterval.Duration == 0 {
		t.Error("rescan interval should default")
	}
	if spec.JobTTLSeconds == 0 {
		t.Error("job TTL should default")
	}
}

func TestReconcileWaitsForConfig(t *testing.T) {
	rep := &depscanv1alpha1.DepScanReport{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "kube-system"},
		Spec:       depscanv1alpha1.DepScanReportSpec{Image: "app:1"},
	}
	c := fake.NewClientBuilder().WithScheme(reportReconcilerScheme()).
		WithObjects(rep).WithStatusSubresource(rep).Build()
	r := &DepScanReportReconciler{Client: c, Config: &ConfigResolver{Client: c}, OperatorNamespace: "depscan-system"}
	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "kube-system", Name: "r"}})
	if err != nil || res.RequeueAfter == 0 {
		t.Fatalf("want a requeue while config is unloaded, got %+v, %v", res, err)
	}
	var jobs batchv1.JobList
	_ = c.List(context.Background(), &jobs)
	if len(jobs.Items) != 0 {
		t.Error("no scan may start before the config is loaded")
	}
}

func TestConfigLoadMissingObjectUsesDefaults(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(reportReconcilerScheme()).Build()
	res := &ConfigResolver{Client: c}
	if res.Loaded() {
		t.Fatal("resolver must start unloaded")
	}
	if err := res.Load(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if !res.Loaded() || res.Get().ScannerImage != Defaults().ScannerImage {
		t.Error("missing DepScanConfig should load the built-in defaults")
	}
}

func TestCapVulnerabilitiesByteBudget(t *testing.T) {
	big := strings.Repeat("y", 400)
	vulns := make([]depscanv1alpha1.Vulnerability, 1900)
	for i := range vulns {
		vulns[i] = depscanv1alpha1.Vulnerability{VulnerabilityID: "CVE", PURL: big, Title: big[:200], PrimaryLink: big}
	}
	got := capVulnerabilities(vulns)
	if len(got) == len(vulns) {
		t.Fatal("expected the byte budget to cut the list")
	}
	b, _ := json.Marshal(got)
	if len(b) > maxStoredVulnerabilityBytes+len(got) {
		t.Errorf("stored findings exceed budget: %d bytes", len(b))
	}
}

func TestRetryDelay(t *testing.T) {
	cfg := depscanv1alpha1.DepScanConfigSpec{RescanInterval: metav1.Duration{Duration: 24 * time.Hour}}
	cases := map[int32]time.Duration{1: 5 * time.Minute, 2: 10 * time.Minute, 4: 40 * time.Minute, 20: 24 * time.Hour}
	for n, want := range cases {
		if got := retryDelay(cfg, n); got != want {
			t.Errorf("retryDelay(%d) = %v, want %v", n, got, want)
		}
	}
}

func TestFailedScanRetriesBeforeRescanInterval(t *testing.T) {
	past := metav1.NewTime(time.Now().Add(-6 * time.Minute))
	rep := &depscanv1alpha1.DepScanReport{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "prod"},
		Spec:       depscanv1alpha1.DepScanReportSpec{Image: "app:1"},
		Status: depscanv1alpha1.DepScanReportStatus{
			Phase: depscanv1alpha1.PhaseFailed, ConsecutiveFailures: 1, UpdateTimestamp: &past,
		},
	}
	c := fake.NewClientBuilder().WithScheme(reportReconcilerScheme()).
		WithObjects(rep).WithStatusSubresource(rep).Build()
	r := &DepScanReportReconciler{Client: c, Config: &ConfigResolver{Client: c, loaded: true}, OperatorNamespace: "depscan-system"}
	if _, err := r.maybeRescan(context.Background(), rep, r.Config.Get(), "depscan-system"); err != nil {
		t.Fatal(err)
	}
	var got depscanv1alpha1.DepScanReport
	_ = c.Get(context.Background(), types.NamespacedName{Namespace: "prod", Name: "r"}, &got)
	if got.Status.Phase != depscanv1alpha1.PhasePending {
		t.Errorf("a failed scan should be retried after its 5m backoff, phase = %q", got.Status.Phase)
	}
}

func TestCollectImagesByDigest(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "reg.example.com/app:latest"}}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
			Name: "app", ImageID: "docker-pullable://reg.example.com/app@sha256:abc",
		}}},
	}
	if _, ok := collectImages(pod, false)["reg.example.com/app:latest"]; !ok {
		t.Error("by default the spec tag is scanned")
	}
	if _, ok := collectImages(pod, true)["reg.example.com/app@sha256:abc"]; !ok {
		t.Error("with scanByDigest the running digest is scanned")
	}
}

func TestReportRecordsNodePlatform(t *testing.T) {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "graviton-1", Labels: map[string]string{
		corev1.LabelOSStable: "linux", corev1.LabelArchStable: "arm64",
	}}}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "prod"},
		Spec:       corev1.PodSpec{NodeName: "graviton-1", Containers: []corev1.Container{{Name: "c", Image: "app:1"}}},
	}
	c := fake.NewClientBuilder().WithScheme(reportReconcilerScheme()).WithObjects(node, pod).Build()
	r := &PodReconciler{Client: c, Config: &ConfigResolver{Client: c, loaded: true}}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "prod", Name: "p"}}); err != nil {
		t.Fatal(err)
	}
	var reports depscanv1alpha1.DepScanReportList
	_ = c.List(context.Background(), &reports)
	if len(reports.Items) != 1 || reports.Items[0].Spec.Platform != "linux/arm64" {
		t.Fatalf("want one report with platform linux/arm64, got %+v", reports.Items)
	}
	rep := &reports.Items[0]
	if got := scanPlatform(depscanv1alpha1.DepScanConfigSpec{}, rep); got != "linux/arm64" {
		t.Errorf("scan platform = %q", got)
	}
	if got := scanPlatform(depscanv1alpha1.DepScanConfigSpec{Platform: "linux/amd64"}, rep); got != "linux/amd64" {
		t.Errorf("config override ignored: %q", got)
	}
}

func TestRequeueOnConflict(t *testing.T) {
	conflict := apierrors.NewConflict(schema.GroupResource{Group: "depscan.io", Resource: "depscanreports"}, "r", nil)
	res, err := requeueOnConflict(ctrl.Result{}, conflict)
	if err != nil || res.RequeueAfter == 0 {
		t.Errorf("conflict should requeue quietly, got %+v, %v", res, err)
	}
	if _, err := requeueOnConflict(ctrl.Result{}, apierrors.NewBadRequest("x")); err == nil {
		t.Error("other errors must pass through")
	}
}

func TestBackfillSummary(t *testing.T) {
	now := metav1.Now()
	rep := &depscanv1alpha1.DepScanReport{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "prod"},
		Spec:       depscanv1alpha1.DepScanReportSpec{Image: "app:1"},
		Status: depscanv1alpha1.DepScanReportStatus{
			Phase: depscanv1alpha1.PhaseCompleted, UpdateTimestamp: &now,
			Summary: depscanv1alpha1.VulnerabilitySummary{HighCount: 2, MediumCount: 1, ReachableCount: 2},
			Vulnerabilities: []depscanv1alpha1.Vulnerability{
				{VulnerabilityID: "a", Severity: depscanv1alpha1.SeverityHigh, Reachability: depscanv1alpha1.ReachabilityReachable},
				{VulnerabilityID: "b", Severity: depscanv1alpha1.SeverityHigh, Reachability: depscanv1alpha1.ReachabilityNotReachable},
				{VulnerabilityID: "c", Severity: depscanv1alpha1.SeverityMedium, Reachability: depscanv1alpha1.ReachabilityReachable},
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(reportReconcilerScheme()).WithObjects(rep).WithStatusSubresource(rep).Build()
	r := &DepScanReportReconciler{Client: c, Config: &ConfigResolver{Client: c, loaded: true}}
	if _, err := r.maybeRescan(context.Background(), rep, r.Config.Get(), "depscan-system"); err != nil {
		t.Fatal(err)
	}
	var got depscanv1alpha1.DepScanReport
	_ = c.Get(context.Background(), types.NamespacedName{Namespace: "prod", Name: "r"}, &got)
	if s := got.Status.Summary; s.TotalCount != 3 || s.ReachableHighCount != 1 || s.ReachableCriticalCount != 0 {
		t.Errorf("summary = %+v", s)
	}
}
