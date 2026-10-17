# Container images

This repository contains custom container images used by the d00s Kubernetes
cluster.

## PostgreSQL backup image

`backup-image/` builds `harbor.apps.d00s.org/d00s/pg-backup`. It is based on PostgreSQL 18.6
and adds the AWS CLI and boto3.

The Argo CD-managed backup CronJobs use the image twice:

1. An init container runs `pg_dump --format=custom` into a shared `emptyDir`.
2. The main container uploads the dump to MinIO and applies the retention
   policy.

Backups are stored in the MinIO bucket `postgres-backup` using separate
`grafana-db-backup-`, `keycloak-db-backup-`, and `kingshot-db-backup-`
prefixes. Database and MinIO credentials are supplied by Kubernetes Secrets;
they are not included in the image.

Kubernetes manifests use an immutable image tag and digest. GitHub Actions
builds both images on relevant pushes, every Sunday, and on manual dispatch.
Each job runs on an ephemeral Kubernetes runner and pushes directly to Harbor.
The runner scales back to zero when the job is complete.

Builds use rootless BuildKit without a privileged Docker daemon. They publish
an immutable date, Git commit, and run-number tag together with SBOM and SLSA
provenance attestations. Harbor automatically scans every pushed artifact.
Copy the reported `tag@digest` from the workflow summary into the d00s GitOps
manifest to promote a build; no mutable `latest` tag is deployed.

See [`backup-image/README.md`](backup-image/README.md) for image-specific
details.

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
