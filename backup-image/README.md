# PostgreSQL backup image

This image contains PostgreSQL 18.6 client tools, the AWS CLI, Python, and
boto3. It can dump PostgreSQL 15 through 18 databases, upload the resulting
archive to an S3-compatible service such as MinIO, and execute the retention
script used by the d00s backup CronJobs.

Use the immutable workflow-produced `18.6-YYYYMMDD-GITSHA-RUN` tag and digest
in Kubernetes. Mutable tags are not published or used in manifests.

The repository workflow builds this directory weekly and whenever its files
change. The image is pushed to `harbor.apps.d00s.org/d00s/pg-backup` with SBOM
and provenance attestations, then Harbor performs its automatic scan.
