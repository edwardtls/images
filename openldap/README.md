# OpenLDAP image

This image builds OpenLDAP 2.6.15 LTS from the upstream source archive and
verifies the archive with its published SHA3-512 checksum. It includes the
MDB backend, syncrepl provider, memberOf, password-policy, and Argon2 modules.

The runtime is Debian 13 slim, runs as UID/GID 10001, and contains no default
directory configuration or credentials. Kubernetes supplies the runtime
configuration, TLS certificate, Vault-managed credentials, and persistent data.

The repository workflow rebuilds this image weekly and whenever its files
change. It publishes to `harbor.apps.d00s.org/d00s/openldap` with SBOM and
provenance attestations, and Harbor automatically scans the result. Kubernetes
manifests must pin the reported manifest digest as well as its immutable tag.
