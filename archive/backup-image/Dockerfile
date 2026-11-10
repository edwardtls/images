FROM postgres:18.6-alpine3.24

LABEL org.opencontainers.image.source="https://github.com/edwardtls/images"
LABEL org.opencontainers.image.description="PostgreSQL 18.6 backup client with Python and boto3"

# Upgrade packages inherited from the PostgreSQL base before installing the
# backup clients. gosu belongs to the upstream database entrypoint, which this
# purpose-built job image does not use; removing it also avoids shipping an
# otherwise unreachable Go runtime in every backup container.
#
# boto3 comes from PyPI rather than Alpine so that it and urllib3 can follow
# upstream fixes, and the AWS CLI with its cryptography stack is not needed.
COPY requirements.txt /opt/backup/requirements.txt
RUN apk upgrade --no-cache && \
    apk add --no-cache python3 && \
    rm -f /usr/local/bin/gosu && \
    python3 -m venv /opt/backup && \
    /opt/backup/bin/pip install --no-cache-dir --no-deps --requirement /opt/backup/requirements.txt && \
    /opt/backup/bin/pip check && \
    /opt/backup/bin/pip uninstall --yes pip && \
    pg_dump --version && \
    /opt/backup/bin/python3 -c 'import boto3; print("boto3", boto3.__version__)'

ENV PATH=/opt/backup/bin:$PATH

# Backup CronJobs provide explicit commands. Do not inherit the PostgreSQL
# server entrypoint, which expects gosu and database-server initialization.
ENTRYPOINT []
CMD ["sh"]
