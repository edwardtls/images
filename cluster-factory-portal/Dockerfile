FROM python:3.14.5-alpine3.22@sha256:6b91e66ab2a880ce9ca5a1b91c70f45963ff71ff68268df056336e1a657d5efd AS audit

WORKDIR /audit
COPY requirements.txt /audit/requirements.txt
RUN apk upgrade --no-cache \
    && pip install --no-cache-dir pip-audit==2.9.0 \
    && pip-audit --requirement /audit/requirements.txt \
    && touch /audit/passed

FROM python:3.14.5-alpine3.22@sha256:6b91e66ab2a880ce9ca5a1b91c70f45963ff71ff68268df056336e1a657d5efd AS runtime

COPY --from=audit /audit/passed /audit-passed

RUN apk upgrade --no-cache \
    && apk add --no-cache openssh-client ca-certificates tini \
    && test -f /audit-passed \
    && rm /audit-passed \
    && addgroup -g 65532 portal \
    && adduser -D -u 65532 -G portal -h /app portal

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --requirement /app/requirements.txt \
    && pip uninstall --yes pip setuptools wheel
COPY app /app/app
RUN chown -R 65532:65532 /app

USER 65532:65532
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
EXPOSE 8080
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "4", "--timeout", "120", "--access-logfile", "-", "--access-logformat", "%(h)s %(l)s %(u)s %(t)s \"%(m)s %(U)s %(H)s\" %(s)s %(b)s \"%(f)s\" \"%(a)s\"", "app.main:app"]
