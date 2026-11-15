#!/usr/bin/env bash
set -Eeuo pipefail
: "${RESTORE_BACKUP_ID:?}"
mkdir -p /restore/data /restore/download
resolved_id="$(python3 - "$RESTORE_BACKUP_ID" <<'PY'
import os, sys, boto3
s3=boto3.client('s3',endpoint_url=os.environ['AWS_ENDPOINT_URL'],region_name='us-east-1',
  aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY'],
  verify=os.environ.get('AWS_CA_BUNDLE',True))
prefix=os.environ.get('S3_PREFIX','forgejo').strip('/')
backup_id=sys.argv[1]
if backup_id == 'latest':
  keys=[]
  for page in s3.get_paginator('list_objects_v2').paginate(Bucket=os.environ['S3_BUCKET'],Prefix=f'{prefix}/'):
    keys.extend(o['Key'] for o in page.get('Contents',[]) if o['Key'].endswith('/manifest.json'))
  if not keys:
    raise SystemExit('no Forgejo backup manifests found')
  backup_id=sorted(keys)[-1].split('/')[-2]
base=f"{prefix}/{backup_id}"
for name in ('manifest.json','forgejo-data.tar.zst'):
  s3.download_file(os.environ['S3_BUCKET'],f'{base}/{name}',f'/restore/download/{name}')
print(backup_id)
PY
)"
echo "Validating backup ${resolved_id}"
expected="$(jq -r .repository.sha256 /restore/download/manifest.json)"
echo "$expected  /restore/download/forgejo-data.tar.zst" | sha256sum -c -
zstd -dc /restore/download/forgejo-data.tar.zst | tar -C /restore/data -xf -
count=0
while IFS= read -r -d '' repo; do
  git --git-dir="$repo" fsck --full
  count=$((count + 1))
done < <(find /restore/data/git/gitea-repositories -type d -name '*.git' -print0)
echo "restore validation succeeded for ${count} repositories"
