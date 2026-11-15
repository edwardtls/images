FROM alpine:3.22.2

LABEL org.opencontainers.image.source="https://git.apps.d00s.org/infra/images"
LABEL org.opencontainers.image.description="Forgejo repository and coordinated CNPG backup client"

COPY requirements.txt /opt/forgejo-backup/requirements.txt
RUN apk upgrade --no-cache && \
    apk add --no-cache bash ca-certificates git jq python3 py3-pip tar zstd && \
    python3 -m venv /opt/forgejo-backup/venv && \
    /opt/forgejo-backup/venv/bin/pip install --no-cache-dir --require-hashes \
      -r /opt/forgejo-backup/requirements.txt && \
    /opt/forgejo-backup/venv/bin/pip check && \
    /opt/forgejo-backup/venv/bin/pip uninstall --yes pip && \
    apk del py3-pip py3-setuptools && \
    rm -rf /root/.cache

COPY backup.sh restore-check.sh kube.py s3.py /opt/forgejo-backup/
RUN chmod 0555 /opt/forgejo-backup/backup.sh /opt/forgejo-backup/restore-check.sh \
      /opt/forgejo-backup/kube.py /opt/forgejo-backup/s3.py && \
    addgroup -g 1000 backup && adduser -D -u 1000 -G backup backup

ENV PATH=/opt/forgejo-backup/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 1000:1000
ENTRYPOINT ["/opt/forgejo-backup/backup.sh"]
