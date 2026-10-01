# Vulnerability database cache

dep-scan downloads a multi-GB vulnerability database (VDB). The cache is
enabled by default (also when no `DepScanConfig` exists). Without a
`claimName`, the operator provisions a
`depscan-vdb-cache` PVC (size, `accessMode`, and `storageClassName`
configurable) and manages the VDB on it:

- A prime Job downloads the VDB into a per-version directory and publishes a
  pointer to the current version. Scans are held in `Pending` ("waiting for
  vulnerability database") until a version is ready, then run against it
  read-only.
- `refreshInterval` (default `24h`) controls how often a new version is primed.
  In-flight scans keep using the version they started on; an old version is
  removed only once no scan still uses it. A refresh always downloads; any
  other prime (for example after an operator restart) reuses the cached
  version named by `latest.meta` when its directory is intact.
- The current version and when it was primed are persisted in the
  `depscan-vdb-state` ConfigMap in the job namespace, so an operator restart
  neither re-downloads the database nor resets the refresh timer. To force a
  fresh download now, delete it
  (`kubectl -n depscan-system delete configmap depscan-vdb-state`): within a
  minute a forced prime starts while scans keep using the current version,
  and the ConfigMap is recreated when it finishes.
- `primeTimeout` (default `4h`) bounds how long a prime Job may run.
- A failed prime is retried with exponential backoff (1 minute, doubling up to
  1 hour) so a broken download source is not hammered.

```yaml
spec:
  vdbCache:
    enabled: true
    size: 100Gi                 # the full database is ~70 GB extracted
    scope: app+os               # "app+os" (full) or "app" (app-only, much smaller)
    accessMode: ReadWriteOnce   # use ReadWriteMany on multi-node clusters
    storageClassName: ""        # empty uses the cluster default StorageClass
    refreshInterval: 24h
```

## Database scope and sizing

`scope` selects how much of the vulnerability database the prime Job downloads:

| Scope | Covers | Approx. size (extracted) | Cache size to use |
|-------|--------|--------------------------|-------------------|
| `app+os` (default) | application + OS/distro packages | ~70 GB | `100Gi` |
| `app` | application-ecosystem packages only | a few GB | `5Gi` |

The full `app+os` database is large. Size the cache for it, including headroom
for the compressed download and extraction. If you only scan application images
without meaningful OS layers, `scope: app` gives a much smaller cache at the
cost of not flagging OS/distro-package CVEs:

```yaml
spec:
  vdbCache:
    enabled: true
    scope: app
    size: 5Gi
```

!!! warning "Default size is for the full database"
    The default `size` suits `app+os`. On a storage class that enforces the
    requested size, an undersized cache fills during the download and the prime
    Job fails. Either keep the default for `app+os` or lower it alongside
    `scope: app`.


## Access mode and multi-node clusters

On multi-node clusters set `accessMode: ReadWriteMany` with an RWX storage
class (for example EFS or NFS) so scan pods on any node share one cache.
`ReadWriteOnce` only works when all scan pods land on a single node: a prime,
GC or scan pod scheduled to another node cannot attach the volume and hangs in
`ContainerCreating` with a `Multi-Attach error` event until its deadline
(`scanTimeout` / `primeTimeout`) fails it. It does not fall back to
downloading the database.

With caching off (`vdbCache.enabled: false`), every scan re-downloads the
database into an `emptyDir` on the node, capped at `vdbCache.size`; the
operator logs a warning at startup. Only do this for small test clusters.

## Override the download source

By default the prime Job fetches the database from dep-scan's built-in public
source. In air-gapped or egress-restricted clusters, point it at an internal
mirror with `downloadURL`:

```yaml
spec:
  vdbCache:
    enabled: true
    downloadURL: registry.example.internal/vdb/vdbxz:v6.7
```

`downloadURL` is an OCI image reference. The operator passes it to the prime
Job as the `VDB_DATABASE_URL` environment variable, which dep-scan uses as the
database source. Leave it empty to use the default source.

!!! note
    The cluster nodes (or the prime Job's pull path) must be able to reach the
    mirror. Mirror the upstream database artifact into your registry first.

!!! note "Mirror and scope together"
    `downloadURL` overrides the full (`app+os`) source. If you mirror an
    app-only database, also set `scope: app` so the prime Job requests the
    matching scope.

## Pre-seed the cache manually

Instead of letting the operator download the database, you can prepare the PVC
yourself and point the operator at it with `claimName`. This is useful when the
cluster has no egress at all, or when you want full control over the database
contents.

The cache PVC holds one directory per database version plus a `latest.meta`
text file naming the current version:

```
/vdbcache/
  <version-key>/        # the extracted database for one version
  latest.meta           # a one-line text file containing <version-key>
```

Steps:

1. Create a PVC (for example `my-vdb-cache`) with a storage class your scan
   pods can mount. Use `ReadWriteMany` on multi-node clusters.
2. Populate it from a helper pod. Mount the PVC, download and extract the
   database into a version directory, then write the pointer file. For example,
   inside a pod with the dep-scan tooling and the PVC mounted at `/vdbcache`:

    ```bash
    key="manual-$(date +%Y-%m-%d)"
    mkdir -p "/vdbcache/$key"
    # Download and extract the VDB into /vdbcache/$key so that the database
    # files live directly under that directory. For an internal mirror:
    #   export VDB_DATABASE_URL=registry.example.internal/vdb/vdbxz:v6.7
    #   VDB_HOME=/vdbcache/$key depscan-vdb download
    printf '%s' "$key" > /vdbcache/latest.meta
    ```

3. Reference the PVC in the config:

    ```yaml
    spec:
      vdbCache:
        enabled: true
        claimName: my-vdb-cache
    ```

When `claimName` is set the operator uses your PVC as-is and does not provision
one. If a `latest.meta` pointer and its version directory are already present,
scans can start immediately without waiting for a prime.

!!! tip
    You can combine both approaches: pre-seed the PVC once for the initial
    cold start, and still set `downloadURL` so the operator's periodic refresh
    pulls newer versions from your mirror.
