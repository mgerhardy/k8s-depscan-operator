package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	depscanv1alpha1 "github.com/mgerhardy/k8s-depscan-operator/api/v1alpha1"
)

// The fake clientset serves "fake logs" for every pod: scan output without any
// report markers. That must fail the scan, never record zero findings.
func TestIngestFailsClosedWithoutReport(t *testing.T) {
	rep := &depscanv1alpha1.DepScanReport{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "prod"},
		Spec:       depscanv1alpha1.DepScanReportSpec{Image: "app:1"},
		Status:     depscanv1alpha1.DepScanReportStatus{Phase: depscanv1alpha1.PhaseScanning, ScanJob: "scan"},
	}
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "scan", Namespace: "depscan-system"}}
	job.Status.Succeeded = 1
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "scan-pod", Namespace: "depscan-system", Labels: map[string]string{"job-name": "scan"},
	}}
	c := fake.NewClientBuilder().WithScheme(reportReconcilerScheme()).
		WithObjects(rep, job, pod).WithStatusSubresource(rep).Build()
	r := &DepScanReportReconciler{
		Client: c, Clientset: k8sfake.NewClientset(pod),
		Config: &ConfigResolver{Client: c, loaded: true}, OperatorNamespace: "depscan-system",
	}
	if _, err := r.ingest(context.Background(), rep, job, r.Config.Get(), "depscan-system"); err != nil {
		t.Fatal(err)
	}
	var got depscanv1alpha1.DepScanReport
	_ = c.Get(context.Background(), types.NamespacedName{Namespace: "prod", Name: "r"}, &got)
	if got.Status.Phase != depscanv1alpha1.PhaseFailed {
		t.Errorf("phase = %q, want Failed (message %q)", got.Status.Phase, got.Status.Message)
	}
}

func TestFinishedScanDeletesCredentials(t *testing.T) {
	rep := &depscanv1alpha1.DepScanReport{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "prod"},
		Spec:       depscanv1alpha1.DepScanReportSpec{Image: "app:1"},
		Status:     depscanv1alpha1.DepScanReportStatus{Phase: depscanv1alpha1.PhaseScanning, ScanJob: "scan"},
	}
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "scan", Namespace: "depscan-system"}}
	job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: scanCredentialsSecretName("prod", "r"), Namespace: "depscan-system",
		Labels: map[string]string{depscanv1alpha1.LabelManagedBy: depscanv1alpha1.ManagedByValue},
	}}
	c := fake.NewClientBuilder().WithScheme(reportReconcilerScheme()).
		WithObjects(rep, job, secret).WithStatusSubresource(rep).Build()
	r := &DepScanReportReconciler{Client: c, Config: &ConfigResolver{Client: c, loaded: true}, OperatorNamespace: "depscan-system"}

	if _, err := r.checkScan(context.Background(), rep, r.Config.Get(), "depscan-system"); err != nil {
		t.Fatal(err)
	}
	var got corev1.Secret
	err := c.Get(context.Background(), types.NamespacedName{Namespace: "depscan-system", Name: secret.Name}, &got)
	if !apierrors.IsNotFound(err) {
		t.Errorf("credentials must be deleted once the scan Job finished, got err=%v", err)
	}
}

func TestJobFinished(t *testing.T) {
	one := int32(1)
	retrying := &batchv1.Job{Spec: batchv1.JobSpec{BackoffLimit: &one}}
	retrying.Status.Failed = 1
	if c, f := jobFinished(retrying); c || f {
		t.Error("a Job with retries left is not finished")
	}
	retrying.Status.Failed = 2
	if _, f := jobFinished(retrying); !f {
		t.Error("a Job past its backoffLimit has failed")
	}
}

func TestExportFailureKeepsResponseBodyOutOfStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal detail: db=10.0.0.5 user=dojo"))
	}))
	defer srv.Close()

	rep := &depscanv1alpha1.DepScanReport{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "prod"},
		Spec:       depscanv1alpha1.DepScanReportSpec{Image: "app:1"},
		Status:     depscanv1alpha1.DepScanReportStatus{Phase: depscanv1alpha1.PhaseCompleted, Message: "3 findings"},
	}
	creds := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "dd", Namespace: "depscan-system"},
		Data:       map[string][]byte{"token": []byte("t")},
	}
	c := fake.NewClientBuilder().WithScheme(reportReconcilerScheme()).
		WithObjects(rep, creds).WithStatusSubresource(rep).Build()
	r := &DepScanReportReconciler{Client: c, Config: &ConfigResolver{Client: c, loaded: true}, OperatorNamespace: "depscan-system"}
	cfg := r.Config.Get()
	cfg.DefectDojo = &depscanv1alpha1.DefectDojoSpec{
		Enabled: true, URL: srv.URL, AllowInsecureURL: true,
		CredentialsSecret: depscanv1alpha1.SecretRef{Name: "dd"},
	}

	r.exportResult(context.Background(), rep, cfg, `{"document":{}}`)

	var got depscanv1alpha1.DepScanReport
	_ = c.Get(context.Background(), types.NamespacedName{Namespace: "prod", Name: "r"}, &got)
	if strings.Contains(got.Status.Message, "internal detail") {
		t.Errorf("response body leaked into status: %q", got.Status.Message)
	}
	if !strings.Contains(got.Status.Message, "HTTP 500") || got.Status.Exported {
		t.Errorf("status should record the failed export, got %q exported=%v", got.Status.Message, got.Status.Exported)
	}
}

func TestDiagnoseJobExplainsFailure(t *testing.T) {
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "scan", Namespace: "depscan-system"}}
	job.Status.Conditions = []batchv1.JobCondition{{
		Type: batchv1.JobFailed, Status: corev1.ConditionTrue,
		Reason: "DeadlineExceeded", Message: "Job was active longer than specified deadline",
	}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "scan-x", Namespace: "depscan-system", Labels: map[string]string{"job-name": "scan"},
	}}
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name:  "depscan",
		State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 137, Reason: "OOMKilled"}},
	}}
	c := fake.NewClientBuilder().WithScheme(reportReconcilerScheme()).WithObjects(job, pod).Build()
	r := &DepScanReportReconciler{Client: c, Clientset: k8sfake.NewClientset(pod)}

	got := r.diagnoseJob(context.Background(), job)
	for _, want := range []string{"DeadlineExceeded", "container depscan exited 137 (OOMKilled)", "fake logs"} {
		if !strings.Contains(got, want) {
			t.Errorf("diagnosis %q missing %q", got, want)
		}
	}
}

func TestDiagnoseJobReportsRejectedPodCreation(t *testing.T) {
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "scan", Namespace: "depscan-system"}}
	ev := &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Name: "scan.1", Namespace: "depscan-system"},
		InvolvedObject: corev1.ObjectReference{Kind: "Job", Name: "scan"},
		Reason:         "FailedCreate",
		Message:        `pods "scan-x" is forbidden: violates PodSecurity "restricted:latest"`,
	}
	c := fake.NewClientBuilder().WithScheme(reportReconcilerScheme()).WithObjects(job, ev).Build()
	r := &DepScanReportReconciler{Client: c}
	if got := r.diagnoseJob(context.Background(), job); !strings.Contains(got, "PodSecurity") {
		t.Errorf("diagnosis should surface the admission rejection, got %q", got)
	}
}

func TestFailedScanEmitsWarningEvent(t *testing.T) {
	rep := &depscanv1alpha1.DepScanReport{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "prod"},
		Spec:       depscanv1alpha1.DepScanReportSpec{Image: "app:1"},
	}
	c := fake.NewClientBuilder().WithScheme(reportReconcilerScheme()).
		WithObjects(rep).WithStatusSubresource(rep).Build()
	rec := events.NewFakeRecorder(4)
	r := &DepScanReportReconciler{Client: c, Recorder: rec, Config: &ConfigResolver{Client: c, loaded: true}}
	if _, err := r.failScan(context.Background(), rep, r.Config.Get(), "scan job failed: OOMKilled"); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-rec.Events:
		if !strings.Contains(e, "Warning ScanFailed") || !strings.Contains(e, "OOMKilled") {
			t.Errorf("unexpected event %q", e)
		}
	default:
		t.Error("no event recorded")
	}
}
