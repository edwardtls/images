FROM python:3.14.10-alpine3.23@sha256:a191e12d3545c23fa0d6d646dd5dcec3ff0b2e8bbc8746db2badad2dcaaa5cc7

ARG BUILD_DATE
ARG VCS_REF
LABEL org.opencontainers.image.title="d00s MCP honeypot" \
      org.opencontainers.image.description="Inert Model Context Protocol telemetry decoy" \
      org.opencontainers.image.created="$BUILD_DATE" \
      org.opencontainers.image.revision="$VCS_REF"

RUN addgroup -S -g 65532 nonroot \
    && adduser -S -D -H -u 65532 -G nonroot nonroot

WORKDIR /app
COPY --chown=65532:65532 server.py /app/server.py

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python", "-I", "/app/server.py"]
