FROM alpine:3.22.2

ARG KUBECTL_VERSION=v1.37.2
ARG KUBECTL_SHA256=c04487523e7aa7d1493f7808174c899db93d7a9cf57531420cd76b9bd415f8f4

LABEL org.opencontainers.image.source="https://github.com/edwardtls/images"
LABEL org.opencontainers.image.description="Forgejo repository and coordinated CNPG backup client"

COPY requirements.txt /opt/forgejo-backup/requirements.txt
RUN apk upgrade --no-cache && \
    apk add --no-cache bash ca-certificates curl git jq python3 py3-pip tar zstd && \
    curl -fsSLo /usr/local/bin/kubectl \
      "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" && \
    echo "${KUBECTL_SHA256}  /usr/local/bin/kubectl" | sha256sum -c - && \
    chmod 0755 /usr/local/bin/kubectl && \
    python3 -m venv /opt/forgejo-backup/venv && \
    /opt/forgejo-backup/venv/bin/pip install --no-cache-dir --require-hashes \
      -r /opt/forgejo-backup/requirements.txt && \
    /opt/forgejo-backup/venv/bin/pip check && \
    rm -rf /root/.cache

COPY backup.sh restore-check.sh s3.py /opt/forgejo-backup/
RUN chmod 0555 /opt/forgejo-backup/backup.sh /opt/forgejo-backup/restore-check.sh \
      /opt/forgejo-backup/s3.py && \
    addgroup -g 1000 backup && adduser -D -u 1000 -G backup backup

ENV PATH=/opt/forgejo-backup/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 1000:1000
ENTRYPOINT ["/opt/forgejo-backup/backup.sh"]
