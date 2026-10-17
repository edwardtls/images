# Container images

This repository contains custom container images used by the d00s Kubernetes
cluster.

## PostgreSQL backup image

`backup-image/` builds `edwardtls1/pg-backup`. It is based on PostgreSQL 18.6
and adds the AWS CLI and boto3.

The Argo CD-managed backup CronJobs use the image twice:

1. An init container runs `pg_dump --format=custom` into a shared `emptyDir`.
2. The main container uploads the dump to MinIO and applies the retention
   policy.

Backups are stored in the MinIO bucket `postgres-backup` using separate
`grafana-db-backup-`, `keycloak-db-backup-`, and `kingshot-db-backup-`
prefixes. Database and MinIO credentials are supplied by Kubernetes Secrets;
they are not included in the image.

Kubernetes manifests use an immutable image tag and digest. After changing the
image, build and push a new version from a Docker-authenticated host, then
update the tag and digest in the d00s GitOps repository:

```sh
cd backup-image
docker build \
  -t edwardtls1/pg-backup:18.6-1 \
  -t edwardtls1/pg-backup:latest \
  .
docker push edwardtls1/pg-backup:18.6-1
docker push edwardtls1/pg-backup:latest
```

See [`backup-image/README.md`](backup-image/README.md) for image-specific
details.

## OpenLDAP image

`openldap/` builds OpenLDAP 2.6.15 LTS directly from the checksum-verified
upstream source release. It is a non-root runtime containing the modules used
by the replicated Kubernetes directory. The image is published to the
internal Harbor project as `harbor.apps.d00s.org/d00s/openldap` and Kubernetes
pins its immutable digest.

See [`openldap/README.md`](openldap/README.md) for build details.
