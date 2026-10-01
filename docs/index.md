# k8s-depscan-operator

A Kubernetes operator that runs [OWASP dep-scan](https://github.com/owasp-dep-scan/dep-scan)
against the container images deployed in your cluster to gather CVE
information, stores the results in CRDs, classifies how network-reachable each
workload is, and can optionally export CSAF VEX reports to DefectDojo.

It discovers every image in use, scans each one, and keeps a `DepScanReport`
per `(namespace, image)` so you can query findings per namespace. Images are
rescanned on a configurable interval.

## How it works

- The operator discovers every container image running in the cluster and
  creates one report per `(namespace, image)` pair.
- Each image is scanned in a short-lived Job. An init container pulls the image
  to a local archive, then dep-scan analyzes it and the operator ingests the
  results.
- Results are stored in a `DepScanReport` custom resource: the CVE list with
  severity, CVSS score, package and fixed version, advisory link, plus a
  network-exposure tier for the workloads running the image.
- A shared vulnerability-database cache keeps the multi-GB dep-scan database on
  a PVC so scans do not each re-download it. See
  [Vulnerability database cache](vdb-cache.md).
- Completed scans can be pushed to DefectDojo as CSAF VEX. See
  [DefectDojo export](defectdojo.md).

## Next steps

- [Deploy](deploy.md) the operator into your cluster.
- [View results](viewing-results.md) and understand the exposure tiers.
- [Configure](configuration.md) scanning scope, scheduling, and resources.

## License

MIT License.
