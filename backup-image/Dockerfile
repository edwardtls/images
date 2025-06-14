# Dockerfile
FROM postgres:17

# Install awscli, python3, boto3 in one layer
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      python3 python3-boto3 awscli \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Entrypoint is inherited from postgres image
