# Network isolation

Scan pods run untrusted image content, so you can restrict their network with
the optional policy in `config/networkpolicy-scan-egress.yaml`:

```bash
kubectl apply -f config/networkpolicy-scan-egress.yaml
```

It denies ingress and allows egress only to DNS and external addresses,
blocking in-cluster and private ranges (RFC1918, CGNAT, IPv6 unique-local),
link-local and loopback, so a compromised scanner cannot reach the API server
(unless it has a public endpoint), other workloads, or the cloud
instance-metadata endpoint (`169.254.169.254`, `fd00:ec2::254`), which can hand
out node credentials.

With NodeLocal DNSCache, pods resolve names via a link-local address (usually
`169.254.20.10`) that the policy blocks; uncomment the DNS `ipBlock` in the
file so scans can resolve registry hosts.

It is not part of `kubectl apply -k config/` because the right egress set is
cluster-specific: if you scan from an in-cluster or private-network registry,
relax the private-range exclusions in that file.

!!! note
    This requires a CNI that enforces NetworkPolicy. On a cluster whose CNI
    ignores NetworkPolicy, the policy has no effect.
