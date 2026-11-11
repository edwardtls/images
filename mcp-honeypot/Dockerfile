FROM python:3.14.10-alpine3.24@sha256:a18b20ad69e74df6cf6d2e1b1a260d7a1ecf5380fd83b310f83ba88c461cf894

ARG BUILD_DATE
ARG VCS_REF
LABEL org.opencontainers.image.title="d00s MCP honeypot" \
      org.opencontainers.image.description="Inert Model Context Protocol telemetry decoy" \
      org.opencontainers.image.created="$BUILD_DATE" \
      org.opencontainers.image.revision="$VCS_REF"

RUN apk upgrade --no-cache \
    && addgroup -S -g 65532 nonroot \
    && adduser -S -D -H -u 65532 -G nonroot nonroot \
    && python -m pip uninstall -y msgpack setuptools urllib3 \
    && rm -rf /root/.cache /usr/local/lib/python*/site-packages/pip

WORKDIR /app
COPY --chown=65532:65532 server.py /app/server.py

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python", "-I", "/app/server.py"]
