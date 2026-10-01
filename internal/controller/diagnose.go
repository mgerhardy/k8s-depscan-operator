package controller

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// maxDiagnosisLen bounds the diagnosis written into status messages.
	maxDiagnosisLen = 1024
	// diagnosisLogLines is how many trailing log lines of a failed container
	// are included.
	diagnosisLogLines = 10
)

// diagnoseJob explains, in one line, why a Job failed or is not making
// progress: the Job's failure condition, the state of its newest pod (exit
// codes, OOM kills, image pull or scheduling problems, the tail of a failed
// container's log), or why no pod could be created (e.g. Pod Security
// admission or a quota). Returns "" when there is nothing notable.
func (r *DepScanReportReconciler) diagnoseJob(ctx context.Context, job *batchv1.Job) string {
	var parts []string
	for _, c := range job.Status.Conditions {
		if c.Type == batchv1.JobFailed && c.Status == corev1.ConditionTrue {
			parts = append(parts, strings.TrimSpace(c.Reason+": "+c.Message))
		}
	}

	pod := r.newestJobPod(ctx, job)
	if pod == nil {
		if ev := r.jobCreateFailure(ctx, job); ev != "" {
			parts = append(parts, "pod not created: "+ev)
		}
	} else {
		parts = append(parts, r.diagnosePod(ctx, pod)...)
	}
	return truncateDiagnosis(strings.Join(nonEmpty(parts), "; "))
}

func (r *DepScanReportReconciler) newestJobPod(ctx context.Context, job *batchv1.Job) *corev1.Pod {
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(job.Namespace), client.MatchingLabels{"job-name": job.Name}); err != nil {
		return nil
	}
	var newest *corev1.Pod
	for i := range pods.Items {
		p := &pods.Items[i]
		if newest == nil || p.CreationTimestamp.After(newest.CreationTimestamp.Time) {
			newest = p
		}
	}
	return newest
}

func (r *DepScanReportReconciler) diagnosePod(ctx context.Context, pod *corev1.Pod) []string {
	var parts []string
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodScheduled && c.Status == corev1.ConditionFalse {
			parts = append(parts, "pod not scheduled: "+c.Message)
		}
	}
	statuses := append(append([]corev1.ContainerStatus(nil), pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...)
	for _, cs := range statuses {
		switch {
		case cs.State.Terminated != nil && cs.State.Terminated.ExitCode != 0:
			t := cs.State.Terminated
			msg := fmt.Sprintf("container %s exited %d", cs.Name, t.ExitCode)
			if t.Reason != "" && t.Reason != "Error" {
				msg += " (" + t.Reason + ")" // e.g. OOMKilled
			}
			if tail := r.logTail(ctx, pod, cs.Name); tail != "" {
				msg += ": " + tail
			}
			parts = append(parts, msg)
		case cs.State.Waiting != nil && cs.State.Waiting.Reason != "" &&
			cs.State.Waiting.Reason != "PodInitializing" && cs.State.Waiting.Reason != "ContainerCreating":
			parts = append(parts, fmt.Sprintf("container %s waiting: %s %s", cs.Name, cs.State.Waiting.Reason, cs.State.Waiting.Message))
		}
	}
	return parts
}

// logTail returns the last lines of a container's log, flattened to one line.
func (r *DepScanReportReconciler) logTail(ctx context.Context, pod *corev1.Pod, container string) string {
	if r.Clientset == nil {
		return ""
	}
	lines := int64(diagnosisLogLines)
	req := r.Clientset.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{Container: container, TailLines: &lines})
	stream, err := req.Stream(ctx)
	if err != nil {
		return ""
	}
	defer func() { _ = stream.Close() }()
	data, err := io.ReadAll(io.LimitReader(stream, maxDiagnosisLen))
	if err != nil {
		return ""
	}
	return strings.Join(strings.Fields(string(data)), " ")
}

// jobCreateFailure returns the latest FailedCreate event message for a Job
// (how Pod Security admission, quota or webhook rejections surface).
func (r *DepScanReportReconciler) jobCreateFailure(ctx context.Context, job *batchv1.Job) string {
	var events corev1.EventList
	if err := r.reader().List(ctx, &events, client.InNamespace(job.Namespace)); err != nil {
		return ""
	}
	var matched []corev1.Event
	for _, e := range events.Items {
		if e.InvolvedObject.Kind == "Job" && e.InvolvedObject.Name == job.Name && e.Reason == "FailedCreate" {
			matched = append(matched, e)
		}
	}
	if len(matched) == 0 {
		return ""
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].LastTimestamp.Before(&matched[j].LastTimestamp) })
	return matched[len(matched)-1].Message
}

func nonEmpty(in []string) []string {
	out := in[:0]
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" && s != ":" {
			out = append(out, s)
		}
	}
	return out
}

func truncateDiagnosis(s string) string {
	if len(s) <= maxDiagnosisLen {
		return s
	}
	cut := maxDiagnosisLen
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut] + "..."
}
