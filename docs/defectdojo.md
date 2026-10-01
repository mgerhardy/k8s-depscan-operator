# DefectDojo export

Export is opt-in. Create a credentials secret, then enable it in the config.

## Credentials

```bash
# Username/password:
kubectl -n depscan-system create secret generic defectdojo-credentials \
  --from-literal=username=admin --from-literal=password='<password>'

# Or an API token (preferred):
kubectl -n depscan-system create secret generic defectdojo-credentials \
  --from-literal=token='<api-token>'
```

## Enable export

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

The CSAF VEX report of every completed scan is uploaded via `reimport-scan`
with `auto_create_context`, so products, engagements, and tests are created on
demand and re-uploads update existing findings instead of duplicating them.

## Options

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Gates all DefectDojo export. |
| `url` | (required) | DefectDojo base URL. |
| `scanType` | `CSAF Scan` | DefectDojo scan type for the upload. |
| `productType` | `Research and Development` | Product type for auto-created products. |
| `engagementName` | `Cluster Dep-Scan Reachability Analysis` | Engagement used for uploads. |
| `productNameTemplate` | `{namespace}` | Product name; supports `{namespace}` and `{image}`. |
| `closeOldFindings` | `true` | Maps to the `reimport-scan` close_old_findings flag. |
| `allowInsecureURL` | `false` | Permit a plain `http://` URL (sends credentials in cleartext). |

!!! warning
    Leave `allowInsecureURL` off unless you have a specific reason. With a plain
    `http://` URL, credentials are sent in cleartext.
