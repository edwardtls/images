# Dockerfile
FROM postgres:17-alpine

# Install awscli, python3, boto3 in one layer
RUN apk add --no-cache python3 aws-cli py3-boto3 && \
    rm -rf /var/cache/apk/*

# Entrypoint is inherited from postgres image
