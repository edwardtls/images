FROM python:3.14-alpine@sha256:bc62fbcb684904b1bb81a6240041bb60e9c1ee19ddeaf17a6b4297e1cc9c95d2

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
