# OpenLDAP image

This image builds OpenLDAP 2.6.15 LTS from the upstream source archive and
verifies the archive with its published SHA3-512 checksum. It includes the
MDB backend, syncrepl provider, memberOf, password-policy, and Argon2 modules.

The runtime is Debian 13 slim, runs as UID/GID 10001, and contains no default
directory configuration or credentials. Kubernetes supplies the runtime
configuration, TLS certificate, sealed credentials, and persistent data.

Build and publish to the internal Harbor project:

```sh
docker build \
  -t harbor.apps.d00s.org/d00s/openldap:2.6.15-1 \
  openldap
docker push harbor.apps.d00s.org/d00s/openldap:2.6.15-1
```

Kubernetes manifests must pin the pushed manifest digest in addition to the
versioned tag.
