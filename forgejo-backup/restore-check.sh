#!/usr/bin/env bash
set -Eeuo pipefail
: "${RESTORE_BACKUP_ID:?}"
mkdir -p /restore/data /restore/download
python3 - "$RESTORE_BACKUP_ID" <<'PY'
import os, sys, boto3
s3=boto3.client('s3',endpoint_url=os.environ['AWS_ENDPOINT_URL'],region_name='us-east-1',
  aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY'],
  verify=os.environ.get('AWS_CA_BUNDLE',True))
base=f"{os.environ.get('S3_PREFIX','forgejo').strip('/')}/{sys.argv[1]}"
for name in ('manifest.json','forgejo-data.tar.zst'):
  s3.download_file(os.environ['S3_BUCKET'],f'{base}/{name}',f'/restore/download/{name}')
PY
expected="$(jq -r .repository.sha256 /restore/download/manifest.json)"
echo "$expected  /restore/download/forgejo-data.tar.zst" | sha256sum -c -
zstd -dc /restore/download/forgejo-data.tar.zst | tar -C /restore/data -xf -
count=0
while IFS= read -r -d '' repo; do
  git --git-dir="$repo" fsck --full
  count=$((count + 1))
done < <(find /restore/data/git/gitea-repositories -type d -name '*.git' -print0)
echo "restore validation succeeded for ${count} repositories"
