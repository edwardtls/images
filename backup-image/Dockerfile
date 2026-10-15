FROM postgres:18.6-alpine

LABEL org.opencontainers.image.source="https://github.com/edwardtls/images"
LABEL org.opencontainers.image.description="PostgreSQL 18.6 backup client with AWS CLI and boto3"

# Install awscli, python3, boto3 in one layer
RUN apk add --no-cache python3 aws-cli py3-boto3 && \
    rm -rf /var/cache/apk/* && \
    pg_dump --version && \
    aws --version && \
    python3 -c 'import boto3; print("boto3", boto3.__version__)'

# The postgres entrypoint is inherited. Kubernetes backup jobs override it.
