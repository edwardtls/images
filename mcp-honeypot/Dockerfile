FROM python:3.15.0-alpine3.23@sha256:d64bc17e0dff27c5c4a31f616450d032aa73d6325855127ce3a305bf1384c8d5

ARG BUILD_DATE
ARG VCS_REF
LABEL org.opencontainers.image.title="d00s MCP honeypot" \
      org.opencontainers.image.description="Inert Model Context Protocol telemetry decoy" \
      org.opencontainers.image.created="$BUILD_DATE" \
      org.opencontainers.image.revision="$VCS_REF"

RUN addgroup -S -g 65532 nonroot \
    && adduser -S -D -H -u 65532 -G nonroot nonroot \
    && python -m pip uninstall -y msgpack setuptools urllib3 \
    && rm -rf /root/.cache /usr/local/lib/python*/site-packages/pip

WORKDIR /app
COPY --chown=65532:65532 server.py /app/server.py

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python", "-I", "/app/server.py"]
