# Metrics

The operator exposes Prometheus metrics on port `8443` (Service
`depscan-operator-metrics` in `depscan-system`).

| Metric | Labels | Description |
|--------|--------|-------------|
| `depscan_scans_completed_total` | `outcome` | Finished scans (`completed` / `failed`). |
| `depscan_scan_duration_seconds` | | Scan duration, Job start to ingestion. |
| `depscan_reports_exported_total` | `outcome` | DefectDojo export attempts. |
| `depscan_vulnerability_count` | `namespace`, `severity` | Current CVE count per namespace and severity. |
| `depscan_reachability_count` | `namespace`, `state` | Current CVE count per namespace and reachability state. |
| `depscan_reports` | `phase` | Reports per phase (`Pending`, `Scanning`, `Completed`, `Failed`). |
| `depscan_vdb_age_seconds` | | Seconds since the current vulnerability database version was primed. |
| `depscan_vdb_info` | `version` | The database version scans use (always 1). |
| `depscan_vdb_prime_failures_total` | | Failed database prime Jobs. |

## Access

The metrics reveal which namespaces carry which vulnerabilities, so the
endpoint is not public: it serves HTTPS and requires a caller whose bearer
token passes a `TokenReview` and who may `get` the `/metrics` non-resource
URL. Bind the shipped `depscan-metrics-reader` ClusterRole to your scraper's
ServiceAccount:

```bash
kubectl create clusterrolebinding depscan-metrics-reader \
  --clusterrole=depscan-metrics-reader \
  --serviceaccount=monitoring:prometheus
```

A Prometheus scrape job then looks like:

```yaml
- job_name: depscan-operator
  scheme: https
  authorization:
    credentials_file: /var/run/secrets/kubernetes.io/serviceaccount/token
  tls_config:
    insecure_skip_verify: true   # the operator uses a self-signed certificate
  static_configs:
    - targets: [depscan-operator-metrics.depscan-system.svc:8443]
```

Telegraf's `inputs.prometheus` works the same way (`bearer_token` plus
`insecure_skip_verify = true`).

To serve plain, unauthenticated HTTP instead (for example when a NetworkPolicy
already restricts who can reach the pod), run the manager with
`--metrics-secure=false --metrics-bind-address=:8080`.

## Alerts

`config/prometheus/alerts.yaml` is an example `PrometheusRule` (Prometheus
Operator) covering a stale or failing vulnerability database, failing scans,
a stuck backlog, and namespaces with reachable vulnerabilities. Adjust the
thresholds to your `refreshInterval` and `rescanInterval`.
