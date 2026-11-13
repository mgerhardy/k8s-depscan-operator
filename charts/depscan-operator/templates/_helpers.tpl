{{/*
This operator is a cluster-scoped singleton: it leader-elects, reconciles one
cluster-wide DepScanConfig, and the vendored RBAC (templates/rbac.yaml) binds
fixed ServiceAccount/Role/ClusterRole names that the controller itself depends
on. Resource names are therefore intentionally fixed, NOT release-prefixed --
two copies in one cluster would fight over the same cluster-scoped objects
regardless. We still emit the standard app.kubernetes.io/instance and /version
labels so tooling (ArgoCD, kubectl selectors) can tell releases apart.
*/}}

{{/*
Selector labels -- the stable subset that must never change for a given
release, used in Deployment/Service selectors and pod template labels.
*/}}
{{- define "depscan-operator.selectorLabels" -}}
app.kubernetes.io/name: k8s-depscan-operator
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: controller-manager
{{- end -}}

{{/*
Common labels for the resources this chart owns directly (namespace,
deployment, service, DepScanConfig). The vendored RBAC/CRD templates carry
their own labels from controller-gen and are left untouched.
*/}}
{{- define "depscan-operator.labels" -}}
app.kubernetes.io/name: k8s-depscan-operator
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{/*
Fully-qualified controller image reference. Digest wins over tag; tag defaults
to the chart appVersion when unset so the image tracks the release the vendored
CRDs/RBAC were generated from.
*/}}
{{- define "depscan-operator.image" -}}
{{- $repo := .Values.image.repository -}}
{{- if .Values.image.digest -}}
{{ $repo }}@{{ .Values.image.digest }}
{{- else -}}
{{ $repo }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}
{{- end -}}
