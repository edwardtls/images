#!/usr/bin/env python3
import datetime as dt
import hashlib
import json
import os
import pathlib
import sys

import boto3
from boto3.s3.transfer import TransferConfig


def client():
    return boto3.client(
        "s3",
        endpoint_url=os.environ["AWS_ENDPOINT_URL"],
        region_name=os.environ.get("AWS_REGION", "us-east-1"),
        aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
        verify=os.environ.get("AWS_CA_BUNDLE", True),
    )


bucket = os.environ["S3_BUCKET"]
prefix = os.environ.get("S3_PREFIX", "forgejo").strip("/")
s3 = client()

if sys.argv[1] == "upload":
    backup_id, archive_name, manifest_name = sys.argv[2:5]
    base = f"{prefix}/{backup_id}"
    config = TransferConfig(multipart_threshold=64 * 1024 * 1024, max_concurrency=2)
    s3.upload_file(archive_name, bucket, f"{base}/forgejo-data.tar.zst", Config=config)
    s3.upload_file(manifest_name, bucket, f"{base}/manifest.json")
    manifest = json.loads(pathlib.Path(manifest_name).read_text())
    body = s3.get_object(Bucket=bucket, Key=f"{base}/forgejo-data.tar.zst")["Body"]
    digest = hashlib.sha256()
    for chunk in iter(lambda: body.read(8 * 1024 * 1024), b""):
        digest.update(chunk)
    if digest.hexdigest() != manifest["repository"]["sha256"]:
        raise SystemExit("uploaded archive checksum mismatch")
elif sys.argv[1] == "prune":
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=int(sys.argv[2]))
    paginator = s3.get_paginator("list_objects_v2")
    doomed = []
    for page in paginator.paginate(Bucket=bucket, Prefix=f"{prefix}/"):
        for obj in page.get("Contents", []):
            if obj["LastModified"] < cutoff:
                doomed.append({"Key": obj["Key"]})
                if len(doomed) == 1000:
                    s3.delete_objects(Bucket=bucket, Delete={"Objects": doomed})
                    doomed = []
    if doomed:
        s3.delete_objects(Bucket=bucket, Delete={"Objects": doomed})
else:
    raise SystemExit("usage: s3.py upload BACKUP_ID ARCHIVE MANIFEST | prune DAYS")
