# PostgreSQL backup image

This image contains PostgreSQL 18.6 client tools, Python, and boto3. It can
dump PostgreSQL 15 through 18 databases, upload the resulting archive to an
S3-compatible service such as MinIO, and execute the upload and retention
scripts used by the d00s backup CronJobs.

boto3 and its dependencies are pinned in `requirements.txt` and installed from
PyPI into `/opt/backup`, which is first on `PATH`. Alpine's packaged AWS CLI and
Python libraries trailed upstream security fixes, and the jobs only need boto3.

The image upgrades packages inherited from the Alpine base during every
no-cache build. It removes the upstream PostgreSQL `gosu` helper and clears the
database-server entrypoint because backup jobs supply explicit commands and do
not initialize or run PostgreSQL locally.

Use the immutable workflow-produced `18.6-YYYYMMDD-GITSHA-RUN` tag and digest
in Kubernetes. Mutable tags are not published or used in manifests.

The repository workflow builds this directory weekly and whenever its files
change. The image is pushed to `harbor.apps.d00s.org/d00s/pg-backup` with SBOM
and provenance attestations, then Harbor performs its automatic scan.
