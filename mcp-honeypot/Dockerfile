FROM python:3.15.0-alpine3.24@sha256:2699b90f4d562a22e2dd076c82f964032f64814204bff36d271a54ba4cc2c7e2

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
