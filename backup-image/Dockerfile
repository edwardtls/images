FROM postgres:18.6-alpine

LABEL org.opencontainers.image.source="https://github.com/edwardtls/images"
LABEL org.opencontainers.image.description="PostgreSQL 18.6 backup client with AWS CLI and boto3"

# Upgrade packages inherited from the PostgreSQL base before installing the
# backup clients. gosu belongs to the upstream database entrypoint, which this
# purpose-built job image does not use; removing it also avoids shipping an
# otherwise unreachable Go runtime in every backup container.
RUN apk upgrade --no-cache && \
    apk add --no-cache python3 aws-cli py3-boto3 && \
    rm -f /usr/local/bin/gosu && \
    pg_dump --version && \
    aws --version && \
    python3 -c 'import boto3; print("boto3", boto3.__version__)'

# Backup CronJobs provide explicit commands. Do not inherit the PostgreSQL
# server entrypoint, which expects gosu and database-server initialization.
ENTRYPOINT []
CMD ["sh"]
