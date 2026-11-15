#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

: "${AWS_ENDPOINT_URL:?}"
: "${AWS_ACCESS_KEY_ID:?}"
: "${AWS_SECRET_ACCESS_KEY:?}"
: "${S3_BUCKET:?}"

namespace=${FORGEJO_NAMESPACE:-forgejo}
deployment=${FORGEJO_DEPLOYMENT:-forgejo}
db_namespace=${CNPG_NAMESPACE:-platform-databases}
db_cluster=${CNPG_CLUSTER:-platform-postgresql}
retention_days=${RETENTION_DAYS:-30}
backup_id="$(date -u +%Y%m%dT%H%M%SZ)-$(cat /proc/sys/kernel/random/uuid | cut -c1-8)"
cnpg_backup="forgejo-${backup_id,,}"
work=/work/${backup_id}
archive=${work}/forgejo-data.tar.zst
manifest=${work}/manifest.json
original_replicas="$(python3 /opt/forgejo-backup/kube.py replicas "$namespace" "$deployment")"
resumed=false

mkdir -p "$work"

resume_forgejo() {
  if [[ "$resumed" == false ]]; then
    python3 /opt/forgejo-backup/kube.py scale "$namespace" "$deployment" "$original_replicas" || true
    python3 /opt/forgejo-backup/kube.py wait-ready "$namespace" "$deployment" "$original_replicas" 300 || true
    resumed=true
  fi
}
trap resume_forgejo EXIT

echo "Quiescing Forgejo (${original_replicas} replicas) for backup ${backup_id}"
python3 /opt/forgejo-backup/kube.py scale "$namespace" "$deployment" 0
python3 /opt/forgejo-backup/kube.py wait-no-pods "$namespace" app.kubernetes.io/name=forgejo 300
quiesced_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

python3 /opt/forgejo-backup/kube.py create-backup "$db_namespace" "$cnpg_backup" "$db_cluster" "$backup_id"

echo "Archiving the quiesced repository volume"
tar --numeric-owner --xattrs --acls \
  --exclude='./tmp/*' --exclude='./log/*' --exclude='./repo-archive/*' \
  -C /data -cf - . | zstd -T0 -10 -o "$archive"
archive_sha256="$(sha256sum "$archive" | awk '{print $1}')"
resume_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
resume_forgejo
trap - EXIT

echo "Waiting for CNPG backup ${cnpg_backup}"
for _ in $(seq 1 180); do
  phase="$(python3 /opt/forgejo-backup/kube.py backup-field "$db_namespace" "$cnpg_backup" phase 2>/dev/null || true)"
  [[ "$phase" == completed ]] && break
  [[ "$phase" == failed ]] && { echo "CNPG backup failed" >&2; exit 1; }
  sleep 10
done
[[ "${phase:-}" == completed ]] || { echo "CNPG backup timed out" >&2; exit 1; }

cnpg_started="$(python3 /opt/forgejo-backup/kube.py backup-field "$db_namespace" "$cnpg_backup" startedAt)"
cnpg_stopped="$(python3 /opt/forgejo-backup/kube.py backup-field "$db_namespace" "$cnpg_backup" stoppedAt)"
archive_size="$(stat -c %s "$archive")"
jq -n \
  --arg backup_id "$backup_id" --arg created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg quiesced_at "$quiesced_at" --arg recovery_target_time "$resume_at" \
  --arg archive "forgejo-data.tar.zst" --arg archive_sha256 "$archive_sha256" \
  --arg cnpg_backup "$cnpg_backup" --arg cnpg_cluster "$db_cluster" \
  --arg cnpg_started "$cnpg_started" --arg cnpg_stopped "$cnpg_stopped" \
  --argjson archive_size "$archive_size" \
  '{schema:1,backup_id:$backup_id,created_at:$created_at,quiesced_at:$quiesced_at,
    recovery_target_time:$recovery_target_time,repository:{object:$archive,sha256:$archive_sha256,size:$archive_size},
    database:{cluster:$cnpg_cluster,backup:$cnpg_backup,started_at:$cnpg_started,completed_at:$cnpg_stopped}}' > "$manifest"

python3 /opt/forgejo-backup/s3.py upload "$backup_id" "$archive" "$manifest"
python3 /opt/forgejo-backup/s3.py prune "$retention_days"
echo "Backup ${backup_id} completed and verified"
