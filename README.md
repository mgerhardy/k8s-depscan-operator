# k8s-depscan-operator

A Kubernetes operator that runs [OWASP dep-scan](https://github.com/owasp-dep-scan/dep-scan)
against the container images deployed in your cluster to gather CVE
**reachability** information, stores the results in CRDs, and can optionally
export CSAF VEX reports to DefectDojo.

It discovers every image in use, scans each one, and keeps a `DepScanReport`
per `(namespace, image)` so you can query findings per namespace. Images are
rescanned on a configurable interval.

## Deploy

```bash
# CRDs, namespace, RBAC, and the controller.
kubectl apply -k config/

# Operator configuration (edit it first; see Configuration below).
kubectl apply -f config/samples/depscanconfig.yaml
```

The operator image is published at `docker.io/mgerhardy/k8s-depscan-operator`.
Pin a released tag in `config/manager/deployment.yaml` for production instead
of `latest`.

## Viewing results

Reports are namespaced custom resources (`DepScanReport`, short name `dsr`):

```bash
kubectl get dsr -A                 # every report, cluster-wide
kubectl get dsr -n <namespace>     # one namespace
kubectl get dsr -n <namespace> <name> -o yaml   # full findings
```

Columns show the image, phase (`Pending` -> `Scanning` -> `Completed` /
`Failed`), the critical/high counts, and how many findings are reachable.
Each entry in `status.vulnerabilities` carries the CVE, severity, CVSS score,
package and version, fixed version, advisory link, and reachability verdict.

> Reachability is reported for application dependencies that dep-scan's code
> analysis can trace. OS/distro packages are not reachability-analyzed, so
> their findings show `unknown`.

## Configuration

A single cluster-scoped `DepScanConfig` named `default` controls the operator.
If it is absent, built-in defaults apply. Full example:
[`config/samples/depscanconfig.yaml`](config/samples/depscanconfig.yaml).

```yaml
apiVersion: depscan.io/v1alpha1
kind: DepScanConfig
metadata:
  name: default
spec:
  scannerImage: ghcr.io/owasp-dep-scan/dep-scan:latest
  rescanInterval: 24h
  jobNamespace: depscan-system
  jobTTLSeconds: 600
  excludeNamespaces: [kube-system, kube-public, kube-node-lease, depscan-system]
  # includeNamespaces: [prod]   # allow-list; overrides excludeNamespaces
  vdbCache:
    enabled: true
    size: 10Gi
    storageClassName: ""        # empty uses the cluster default StorageClass
  resources:
    requests: {cpu: 250m, memory: 512Mi}
    limits: {cpu: "2", memory: 2Gi}
```

### Which namespaces are scanned

- `excludeNamespaces` - never scanned. Good for system namespaces.
- `includeNamespaces` - when set, scanning is restricted to this allow-list
  (and `excludeNamespaces` is ignored).

Changing scope also cleans up: reports in a namespace that falls out of scope
are removed on the next reconcile.

### Scan scheduling

`rescanInterval` (a Go duration like `24h`, `6h`, `30m`) is how long a report
stays valid before its image is rescanned. `jobTTLSeconds` is how long finished
scan Jobs are kept before Kubernetes garbage-collects them.
`maxConcurrentScans` caps how many scans run at once so a burst of new images
does not create many heavy scan pods simultaneously.

### Vulnerability database cache

dep-scan downloads a multi-GB vulnerability database on first run. With
`vdbCache.enabled: true` and no `claimName`, the operator provisions a
`depscan-vdb-cache` PVC (size and `storageClassName` configurable) and reuses
it across scans. Set `claimName` to use a PVC you manage. With caching off,
every scan re-downloads the database into an `emptyDir`.

### Private registries

Images are pulled over the registry API using the pull secrets
(`imagePullSecrets`) of the workloads that run them, so private registries work
without extra configuration as long as the workloads can already pull them.

### Network isolation (optional)

Scan pods run untrusted image content, so you can restrict their network with
the optional policy in
[`config/networkpolicy-scan-egress.yaml`](config/networkpolicy-scan-egress.yaml):

```bash
kubectl apply -f config/networkpolicy-scan-egress.yaml
```

It denies ingress and allows egress only to DNS and external addresses,
blocking in-cluster/private ranges so a compromised scanner cannot reach the
API server or other workloads. It is not part of `kubectl apply -k config/`
because the right egress set is cluster-specific: if you scan from an
in-cluster or private-network registry, relax the private-range exclusions in
that file. Requires a CNI that enforces NetworkPolicy.

## DefectDojo export

Export is opt-in. Create a credentials secret, then enable it in the config:

```bash
# Username/password:
kubectl -n depscan-system create secret generic defectdojo-credentials \
  --from-literal=username=admin --from-literal=password='<password>'

# Or an API token (preferred):
kubectl -n depscan-system create secret generic defectdojo-credentials \
  --from-literal=token='<api-token>'
```

```yaml
spec:
  defectDojo:
    enabled: true
    url: https://defectdojo.example
    productNameTemplate: "{namespace}"   # one DefectDojo product per namespace
    engagementName: Cluster Dep-Scan Reachability Analysis
    closeOldFindings: true
    credentialsSecret:
      name: defectdojo-credentials
      namespace: depscan-system
```

The CSAF VEX report of every completed scan is uploaded via
`reimport-scan` with `auto_create_context`, so products, engagements, and tests
are created on demand and re-uploads update existing findings instead of
duplicating them. `productNameTemplate` supports `{namespace}` and `{image}`.

## License

MIT License. See [LICENSE](LICENSE).
