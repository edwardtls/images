# Refoss/Tasmota exporter

This image replaces the legacy `edwardtls1/refoss_exporter:latest` deployment.
It collects a fixed list of private Tasmota/Refoss outlets and exposes their
power metrics on `/metrics`.

The inventory is supplied through `DEVICES_JSON` by the d00s GitOps repository.
Callers cannot select an arbitrary target, which prevents the exporter from
being used as an SSRF proxy. Collection is concurrent, bounded to four workers,
and each outlet has a short timeout. One unavailable outlet does not fail the
Prometheus scrape.

The runtime:

- uses only the Python standard library;
- removes the unused pip, setuptools, and vendored package installer modules
  from the runtime image;
- runs as UID/GID 65532;
- contains no package manager dependencies or credentials;
- is built weekly with an SBOM and provenance attestation;
- is scanned by Harbor and deployed by immutable tag and digest;
- is restricted by Kubernetes NetworkPolicy to the IoT subnet and Prometheus.

Example inventory:

```json
[
  {"name": "pve0", "ip": "192.168.41.4"},
  {"name": "pve1", "ip": "192.168.41.3"}
]
```

The source was derived from `edwardtls/refoss_exporter`, which in turn forked
`astr0n8t/tasmota-power-exporter`. Version 2 consolidates all outlets into one
process and preserves the established `tasmota_*` metric names.
