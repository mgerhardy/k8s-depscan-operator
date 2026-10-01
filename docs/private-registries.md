# Private registries

Images are pulled over the registry API using the pull secrets
(`imagePullSecrets`) of the workloads that run them, so private registries work
without extra configuration as long as the workloads can already pull their own
images.

For each image, the operator collects the pull secrets referenced by the pods
running that image and builds the registry credentials the pull needs. Wildcard
registry entries (for example `*.example.com`) are resolved to the image's
concrete host so the pull is authenticated correctly.

Only the credentials for the image's own registry are used. They are written
to a short-lived Secret in the job namespace, mounted into the pull step only,
and deleted as soon as the scan Job finishes.

No operator-wide registry credentials are required. If a workload can pull its
image, the operator can scan it.
