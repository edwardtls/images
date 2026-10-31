FROM python:3.14-alpine@sha256:bc62fbcb684904b1bb81a6240041bb60e9c1ee19ddeaf17a6b4297e1cc9c95d2

ARG BUILD_DATE
ARG VCS_REF
LABEL org.opencontainers.image.title="d00s Refoss/Tasmota exporter" \
      org.opencontainers.image.description="Fixed-inventory Prometheus exporter for Tasmota power outlets" \
      org.opencontainers.image.created="$BUILD_DATE" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.source="https://github.com/edwardtls/images/tree/main/refoss-exporter"

RUN addgroup -S -g 65532 nonroot \
    && adduser -S -D -H -u 65532 -G nonroot nonroot \
    && rm -rf /usr/local/lib/python3.14/site-packages/pip* \
              /usr/local/lib/python3.14/ensurepip \
              /usr/local/bin/pip*

WORKDIR /app
COPY --chown=65532:65532 exporter.py /app/exporter.py

USER 65532:65532
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
EXPOSE 8000
ENTRYPOINT ["python", "-I", "/app/exporter.py"]
