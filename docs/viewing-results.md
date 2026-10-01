# Viewing results

Reports are namespaced custom resources (`DepScanReport`, short name `dsr`):

```bash
kubectl get dsr -A                               # every report, cluster-wide
kubectl get dsr -n <namespace>                   # one namespace
kubectl get dsr -n <namespace> <name> -o yaml    # full findings
```

!!! note "Who can read reports"
    The install ships a `depscan-report-viewer` ClusterRole aggregated into the
    built-in `view`, `edit` and `admin` roles, so anyone with one of those in a
    namespace can read that namespace's reports without extra RBAC.

## Columns

| Column | Meaning |
|--------|---------|
| `Phase` | `Pending` -> `Scanning` -> `Completed` / `Failed`. |
| `Total` | All findings. |
| `Critical`, `High` | Findings of that severity, reachable or not. |
| `Reach Crit`, `Reach High` | Critical / high findings dep-scan marked reachable: fix these first. |
| `Reachable` | Reachable findings of **any** severity (medium and low included), so it can be larger than `Critical` + `High`. |
| `Exposure` | The workload's network exposure (see below). |
| `Last Scan` | When the report was last updated. |

`kubectl get dsr -o wide` adds `Medium`, `Low` and the status `Message`
(which explains failed or waiting scans).

For example, `Critical 3  High 26  Reach Crit 0  Reach High 20  Reachable 33`
means none of the critical CVEs is reachable, 20 of the 26 high ones are, and
13 more reachable findings are medium or low.

Each entry in `status.vulnerabilities` carries the CVE, severity, CVSS score,
package and version, fixed version, advisory link, and a reachability verdict.

## Summary counts

`status.summary` aggregates the findings for the image. The severity counts
partition every finding into exactly one bucket, so they add up to the total
number of findings:

| Field | Meaning |
|-------|---------|
| `totalCount` | All findings. |
| `criticalCount` | Findings rated critical severity. |
| `highCount` | Findings rated high severity. |
| `mediumCount` | Findings rated medium (or moderate) severity. |
| `lowCount` | Findings rated low severity. |
| `noneCount` | Findings rated none/informational (no meaningful severity, e.g. CVSS 0). |
| `unknownCount` | Findings whose severity could not be determined (missing or unrecognized rating). |
| `reachableCount` | Findings dep-scan analyzed and found reachable (vulnerable code on an execute path). |
| `notReachableCount` | Findings dep-scan analyzed and found not reachable (code present but not on an execute path). |
| `unknownReachabilityCount` | Findings with no reachability data (not covered by analysis, e.g. OS/distro packages). |
| `reachableCriticalCount` | Critical findings marked reachable. |
| `reachableHighCount` | High findings marked reachable. |

The three reachability counts partition the findings just like the severity
counts do. `status.reachabilityAnalyzed` is `true` when dep-scan ran
reachability analysis for the image at all.

!!! note
    `unknownCount` is about **severity**, not reachability. A finding with
    unknown severity is unrelated to a CVE whose reachability verdict is
    `unknown`. The severity counts and the reachability counts are two separate
    partitions of the same findings.

## Network exposure

`status.exposure` classifies how network-reachable the workloads running the
image are. It is the strongest signal for whether an image CVE is actually
exploitable.

| Tier | Meaning |
|------|---------|
| `internet` | Reachable from the public internet: a LoadBalancer, Ingress or Gateway API route (`HTTPRoute`/`GRPCRoute`) on a public address. An Ingress or Gateway that reports no address is assumed internet-facing. |
| `network-adjacent` | Reachable from the local network: a LoadBalancer, Ingress or Gateway on a private (RFC1918/CGNAT) address, or a NodePort. |
| `cluster-internal` | Reachable only inside the cluster (ClusterIP only). |
| `not-a-service` | No Service routes to it (init container or no Service). |

Exposure is recomputed whenever a Service, Ingress or Gateway API route in the
namespace changes.

## Reachability

For each finding the operator records one of three reachability verdicts,
derived from dep-scan's CSAF VEX output:

| Verdict | Meaning |
|---------|---------|
| `reachable` | dep-scan traced the vulnerable code to a path present in the image. |
| `not-reachable` | dep-scan analyzed the code and the vulnerable path is not reachable (present but not on an execute path). |
| `unknown` | No reachability data: the finding was not covered by analysis (e.g. OS/distro packages, or code dep-scan could not trace). |

`status.reachabilityAnalyzed` tells you whether reachability analysis ran for
the image at all. This disambiguates the two reasons a report can show zero
reachable findings:

- `reachabilityAnalyzed: true` with `reachableCount: 0` means dep-scan checked
  and found nothing reachable.
- `reachabilityAnalyzed: false` means reachability was never determined (for
  example an OS-only image with no analyzable application code) - zero
  reachable does **not** mean the image is safe by reachability.

Reachability analysis runs when the `research` scan profile (the default) is
used and the image contains analyzable application code; images whose findings
are all OS/distro packages are reported as not analyzed.

!!! note
    Reachability narrows *which code is callable*; the network-exposure tier
    above narrows *whether that code is attacker-reachable*. Read them together:
    a reachable CVE in an `internet`-exposed workload is the highest priority.


## Events

The operator records Kubernetes Events on each report: `ScanStarted`,
`ScanCompleted` (with the findings summary), and the warnings `ScanFailed`
(with the diagnosis) and `ExportFailed`. They show up in
`kubectl describe dsr <name>` and in `kubectl get events -n <namespace>`.

## Rescanning an image

Reports are rescanned every `rescanInterval`, and failed scans retry with
backoff. To rescan one image now:

```bash
kubectl -n <namespace> annotate dsr <report-name> depscan.io/rescan=now
```

The operator removes the annotation and queues the scan (this needs `patch`
on `depscanreports`, which the read-only tenant role does not grant; bind the
`depscan-report-editor` ClusterRole to delegate it).
