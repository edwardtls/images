# Container images

This repository contains custom container images used by the d00s Kubernetes
cluster.

## Builds

Kubernetes manifests use an immutable image tag and digest. GitHub Actions
builds every image on relevant pushes, every Sunday, and on manual dispatch.
Each job runs on an ephemeral Kubernetes runner and pushes directly to Harbor.
The runner scales back to zero when the job is complete.

Builds use rootless BuildKit without a privileged Docker daemon. They publish
an immutable date, Git commit, and run-number tag together with SBOM and SLSA
provenance attestations. Harbor automatically scans every pushed artifact.
Copy the reported `tag@digest` from the workflow summary into the d00s GitOps
manifest to promote a build; no mutable `latest` tag is deployed.

Retired images are kept under [`archive/`](archive/README.md) and are not
built.

## Refoss/Tasmota power exporter

`refoss-exporter/` builds `harbor.apps.d00s.org/d00s/refoss-exporter`. One
non-root process collects the fixed, GitOps-managed outlet inventory and
exports compatible Tasmota power metrics. It uses only Python's standard
library, accepts no caller-supplied target, and replaces the legacy pod per
outlet deployment from Docker Hub.

See [`refoss-exporter/README.md`](refoss-exporter/README.md) for configuration
and security details.

## OpenLDAP image

`openldap/` builds OpenLDAP 2.6.15 LTS directly from the checksum-verified
upstream source release. It is a non-root runtime containing the modules used
by the replicated Kubernetes directory. The image is published to the
internal Harbor project as `harbor.apps.d00s.org/d00s/openldap` and Kubernetes
pins its immutable digest.

The workflow has no `pull_request` trigger because this repository is public
and a self-hosted runner must not execute untrusted fork code. Only trusted
pushes to `main`, schedules, and manual dispatches can start it.

See [`openldap/README.md`](openldap/README.md) for build details.

## Cluster Factory Portal

`cluster-factory-portal/` provides the Keycloak-authenticated web portal,
short-lived Ansible trigger, and read-only inventory observer for disposable
clusters. The web process contains no Proxmox credentials or disposable
cluster kubeconfigs. Build/delete work runs as audited Kubernetes Jobs and
calls the existing playbooks on Atlantis over the restricted factory SSH key.

The same immutable image is used for the web, runner, and observer roles. The
GitOps deployment pins a promoted `tag@digest`; no mutable tag is deployed.
