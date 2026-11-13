# depscan-operator Helm chart

Installs the k8s-depscan-operator: the `depscan-system` namespace, the
`DepScanConfig`/`DepScanReport` CRDs, the operator's RBAC, and the controller
Deployment. Optionally also the single `DepScanConfig` that gives the operator
its scan scope.

This is the same install as `kubectl apply -k config/`, packaged for Helm/ArgoCD
and with the image, resources, placement and namespace exposed as values.

## Install

```bash
helm install depscan-operator ./charts/depscan-operator

# Pin a specific build (recommended) and keep CRDs/RBAC in lockstep with it:
helm install depscan-operator ./charts/depscan-operator \
  --set image.digest=sha256:<digest>
```

By default the image tracks the chart's `appVersion`. Set `image.tag` to track a
different release tag, or `image.digest` to pin by digest (digest wins over
tag). The operator is **inert until a `DepScanConfig` exists** -- either enable
the bundled one (`--set config.enabled=true`, see `values.yaml`) or apply your
own (`config/samples/depscanconfig.yaml`).

## Values

See [`values.yaml`](./values.yaml) for the full, annotated list. The common
knobs:

| Key | Default | Purpose |
|-----|---------|---------|
| `namespace` | `depscan-system` | Namespace for the operator, RBAC and scan Jobs. |
| `createNamespace` | `true` | Let the chart create the namespace (with the required PodSecurity labels). |
| `image.repository` | `docker.io/mgerhardy/k8s-depscan-operator` | Controller image. |
| `image.tag` / `image.digest` | `""` / `""` | Pin the build; empty tag -> `appVersion`. Digest wins. |
| `resources` | 50m/128Mi .. 500m/512Mi | Controller requests/limits. |
| `metricsService.enabled` | `true` | Create the authenticated metrics Service. |
| `podSecurityContext` / `securityContext` | hardened (non-root, RO rootfs, drop ALL) | Pod/container security contexts; override as needed. |
| `podAnnotations` / `podLabels` | `{}` | Extra metadata on the controller pod. |
| `config.enabled` | `false` | Ship the cluster-scoped `DepScanConfig` from the chart. |

## How the chart is maintained

The chart has two halves:

- **Vendored, generated** -- `templates/crds.yaml` and `templates/rbac.yaml` are
  produced by `hack/gen-helm-chart.sh` straight from the controller-gen output
  under `config/crd` and `config/rbac`, so they can never drift from the binary
  that watches/writes those resources. They carry a `DO NOT EDIT` header. The
  only transform applied is rewriting the literal `depscan-system` namespace to
  `{{ .Values.namespace }}` so the install can be relocated.
- **Hand-written, templated** -- `namespace.yaml`, `deployment.yaml`,
  `service.yaml`, `depscanconfig.yaml`, `NOTES.txt`, `_helpers.tpl`.

Regenerate the vendored half after changing `api/` types or RBAC markers:

```bash
make helm        # runs `make generate` then hack/gen-helm-chart.sh
make helm-lint   # helm lint + template smoke test
```
