# Configuration

A single cluster-scoped `DepScanConfig` named `default` controls the operator
(other names are rejected at admission).
If it is absent, built-in defaults apply. A full example lives at
`config/samples/depscanconfig.yaml`.

The operator reads the config at startup before it reconciles anything and
exits if the API server cannot be reached, rather than briefly running with an
empty (scan-everything) scope. Changes are picked up as soon as they are
applied.

```yaml
apiVersion: depscan.io/v1alpha1
kind: DepScanConfig
metadata:
  name: default
spec:
  scannerImage: ghcr.io/owasp-dep-scan/dep-scan:v6.3.0
  scanProfile: research   # "research" enables reachability; "generic" is faster
  rescanInterval: 24h
  jobNamespace: depscan-system
  jobTTLSeconds: 600
  maxConcurrentScans: 5
  excludeNamespaces: [kube-system, kube-public, kube-node-lease, depscan-system]
  # includeNamespaces: [prod]   # allow-list; excludeNamespaces still wins
  vdbCache:
    enabled: true
    scope: app+os               # full DB (OS + app CVEs), ~70 GB extracted
    size: 100Gi                 # for scope "app" (app-only CVEs) 5Gi is enough
    accessMode: ReadWriteOnce   # ReadWriteMany (EFS/NFS) on multi-node clusters
    storageClassName: ""        # empty uses the cluster default StorageClass
  resources:
    requests: {cpu: 250m, memory: 512Mi}
    limits: {cpu: "2", memory: 2Gi}
```

## Which namespaces are scanned

- `excludeNamespaces` - never scanned. Good for system namespaces. Takes
  precedence over `includeNamespaces`.
- `includeNamespaces` - when set, scanning is restricted to this allow-list.

Both lists accept shell-style glob patterns (for example `team-*`, `*-prod`,
`app-?`); an entry with no glob characters is matched exactly. A namespace is
scanned when it matches an `includeNamespaces` entry (or the list is empty) and
matches no `excludeNamespaces` entry.

```yaml
spec:
  excludeNamespaces: ["*-system", kube-public]
  includeNamespaces: ["team-*"]   # scan team-a, team-b, ... but not team-system
```

Changing scope also cleans up: reports in a namespace that falls out of scope
are removed on the next reconcile.

## Scan scheduling

- `rescanInterval` (a Go duration like `24h`, `6h`, `30m`) is how long a report
  stays valid before its image is rescanned.
- `jobTTLSeconds` is how long finished scan Jobs are kept before Kubernetes
  garbage-collects them.
- `maxConcurrentScans` caps how many scans run at once so a burst of new images
  does not create many heavy scan pods simultaneously.
- `scanTimeout` (default `1h`) fails a scan Job that runs longer, so a hanging
  or pathological image cannot hold a scan slot forever.
- `scanWorkSizeLimit` (default `20Gi`) caps the scratch volume holding the
  pulled image archive. A scan of a larger image is evicted instead of filling
  the node's disk; raise it if you scan very large images.

## Scanning by digest

By default the operator scans the image reference from the pod spec (for
example `app:latest`), because some registries do not serve manifests by
digest. A moved tag can then make a report describe a different build than the
one running. Set `scanByDigest: true` to scan the digest each container
actually runs (from the pod status). Reports are then per digest: a new build
gets a new report and the old one is pruned once no pod runs it.

## Architecture

Multi-arch images are pulled in the variant matching the node each image runs
on (recorded in the report's `spec.platform`), so images on arm64 nodes are
scanned as arm64. Set `platform: linux/amd64` (or another `os/arch`) to force
one variant for every scan.

## Scan profile

`scanProfile` is dep-scan's analysis profile. `research` (the default) enables
reachability analysis for application dependencies; `generic` is a faster scan
without it. Other dep-scan profiles are also accepted.

## Images

- `scannerImage` is the dep-scan container image to run. The defaults for both
  images are pinned by digest so every node runs the same build; if you
  override them, prefer `name:tag@sha256:...` over a moving tag like `latest`.
- `craneImage` is the image used to pull each target image from its registry
  before scanning. The default works for public and private registries.

## Resources

`resources.requests` and `resources.limits` are applied to scan Jobs. The
dep-scan database and image analysis are memory-hungry, so size limits
generously for large images.

## Validation

The CRD validates sizes (Kubernetes quantities such as `100Gi`), durations
(Go durations such as `24h` or `90m`), resource names and values, and the
DefectDojo URL scheme, so a typo like `size: 10GB` or `rescanInterval: 1d` is
rejected by `kubectl apply` instead of failing later at runtime. CEL rules
need Kubernetes 1.25 or newer.

## Full reference

| Field | Default | Description |
|-------|---------|-------------|
| `scannerImage` | `ghcr.io/owasp-dep-scan/dep-scan:v6.3.0` (pinned by digest) | dep-scan image to run. |
| `craneImage` | `gcr.io/go-containerregistry/crane:v0.22.1` (pinned by digest) | Image used to pull target images. |
| `scanProfile` | `research` | dep-scan analysis profile. |
| `rescanInterval` | `24h` | How long a report stays valid. |
| `jobNamespace` | operator namespace | Where scan Jobs are created. Needs the namespaced RBAC there (see [Deploy](deploy.md)); changing it restarts the operator. |
| `jobTTLSeconds` | `600` | TTL for finished scan Jobs. |
| `maxConcurrentScans` | `5` | Cap on simultaneous scan Jobs. |
| `scanByDigest` | `false` | Scan the running digest instead of the spec tag. |
| `platform` | node's os/arch | Force the `os/arch` pulled for every scan. |
| `scanTimeout` | `1h` | Deadline for a scan Job. |
| `scanWorkSizeLimit` | `20Gi` | Size limit of the image-archive scratch volume. |
| `includeNamespaces` | (unset) | Allow-list of namespaces to scan. |
| `excludeNamespaces` | (unset) | Namespaces to never scan. |
| `vdbCache` | enabled, `100Gi` | Vulnerability database cache. See [Vulnerability database cache](vdb-cache.md). |
| `resources` | (unset) | Resource requests/limits for scan Jobs. |
| `defectDojo` | disabled | CSAF VEX export. See [DefectDojo export](defectdojo.md). |
