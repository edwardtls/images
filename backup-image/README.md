# PostgreSQL backup image

This image contains PostgreSQL 18.6 client tools, the AWS CLI, Python, and
boto3. It can dump PostgreSQL 15 through 18 databases, upload the resulting
archive to an S3-compatible service such as MinIO, and execute the retention
script used by the d00s backup CronJobs.

Use the immutable `18.6-1` tag in Kubernetes. `latest` is published only as a
convenience tag and should not be used in manifests.

# build images
```
docker build \
  -t edwardtls1/pg-backup:18.6-1 \
  -t edwardtls1/pg-backup:latest \
  .
```

# push images
```
docker push edwardtls1/pg-backup:18.6-1
docker push edwardtls1/pg-backup:latest
```
