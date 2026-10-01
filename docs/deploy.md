# Deploy

## Install

```bash
# CRDs, namespace, RBAC, and the controller.
kubectl apply -k config/

# Operator configuration (edit it first; see Configuration).
kubectl apply -f config/samples/depscanconfig.yaml
```

The operator image is published at `docker.io/mgerhardy/k8s-depscan-operator`.

!!! tip "Image tag"
    `config/manager/deployment.yaml` uses `latest` (built from `main`) with
    `imagePullPolicy: Always`. For reproducible installs, pin a release tag or
    digest there instead.

## What gets created

- A `depscan-system` namespace for the controller and the scan Jobs, labeled
  for the `baseline` Pod Security Standard. Scan pods run as root (dep-scan
  reads root-owned image layers), so the namespace cannot enforce
  `restricted`; they still drop all capabilities, block privilege escalation
  and use the `RuntimeDefault` seccomp profile. If your cluster manages
  Pod Security centrally (Kyverno, Gatekeeper, a PSA exemption list), allow
  these pods there as well.
- The `DepScanConfig` (cluster-scoped) and `DepScanReport` (namespaced) CRDs.
- A ServiceAccount, Role/ClusterRole, and bindings for the controller. The
  ClusterRole is read-only apart from `DepScanReport`s (pods, services,
  ingresses, configs, and `get` on the pull secrets of scanned workloads).
  Everything the operator creates or deletes (Jobs, short-lived credential
  Secrets, the VDB cache PVC and state ConfigMap) is granted by a Role in
  `depscan-system` only. If you set `jobNamespace` to another namespace, create
  the `depscan-operator` Role and RoleBinding from `config/rbac` there too.
- The controller Deployment (a single leader-elected pod).

## Verify the install

```bash
# The controller pod should be Running.
kubectl -n depscan-system get pods

# The config should be accepted and healthy: Valid and VDB Ready "True".
# The first VDB prime downloads tens of GB, so VDB Ready stays "False"
# (reason Priming) for a while; status.conditions explains any problem.
kubectl get depscanconfig default
kubectl get depscanconfig default -o jsonpath='{.status}'

# Reports start appearing as images are discovered and scanned.
kubectl get dsr -A
```

## Running scans in another namespace

By default scan Jobs run in `depscan-system`. To use another namespace (for
example one with dedicated nodes or quotas), prepare it before setting
`spec.jobNamespace`:

1. Create the namespace with the Pod Security labels scan pods need:

    ```bash
    kubectl create namespace depscan-jobs
    kubectl label namespace depscan-jobs \
      pod-security.kubernetes.io/enforce=baseline \
      pod-security.kubernetes.io/enforce-version=latest
    ```

2. Grant the operator its namespaced permissions there: copy the `Role`
   from `config/rbac/role.yaml` and the `depscan-operator` `RoleBinding`
   from `config/rbac/service_account.yaml`, changing only
   `metadata.namespace` (the binding's subject stays the ServiceAccount in
   `depscan-system`).
3. If you use the scan egress policy, apply
   `config/networkpolicy-scan-egress.yaml` with `metadata.namespace` changed
   as well.
4. Set `spec.jobNamespace: depscan-jobs`. The operator restarts itself to
   re-scope its caches; the VDB cache PVC and state are created anew in the
   new namespace (the first prime downloads the database again).
5. Check `kubectl get dsc default`: `Valid` turns `False` with an explanation
   if the RBAC from step 2 is missing.

Leader election, metrics and the operator Deployment stay in
`depscan-system`.

## Uninstall

```bash
kubectl delete -f config/samples/depscanconfig.yaml
kubectl delete -k config/
```

Deleting the CRDs removes all `DepScanReport` objects with them. Deleting the
`depscan-system` namespace also deletes the VDB cache PVC (and the downloaded
database). Left behind and to be removed by hand: a custom `jobNamespace` with
its PVC, Role and RoleBinding; a PVC you supplied via `vdbCache.claimName`;
and the aggregated ClusterRoles if you applied them separately.
