FROM python:3.13.18-alpine3.24@sha256:1e1f6334529d1fb26a2ef619d7cffb30a7c7d7cc1cc7338ebee283a58d1aeaca AS audit

WORKDIR /audit
COPY requirements.txt /audit/requirements.txt
RUN apk upgrade --no-cache \
    && pip install --no-cache-dir pip-audit==2.9.0 \
    && pip-audit --requirement /audit/requirements.txt \
    && touch /audit/passed

FROM python:3.13.18-alpine3.24@sha256:1e1f6334529d1fb26a2ef619d7cffb30a7c7d7cc1cc7338ebee283a58d1aeaca AS runtime

ARG VCS_REF=dev

COPY --from=audit /audit/passed /audit-passed

# The portal does not use SQLite, so its library and Python module are removed
# with the rest of Python's runtime dependencies kept.
RUN apk upgrade --no-cache \
    && apk add --no-cache openssh-client ca-certificates tini \
    && apk add --no-cache libbz2 libffi gdbm xz-libs ncurses-libs readline libssl3 libcrypto3 libuuid zlib \
    && apk del --no-cache .python-rundeps sqlite-libs \
    && rm -rf /usr/local/lib/python3.13/sqlite3 /usr/local/lib/python3.13/lib-dynload/_sqlite3.*.so \
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
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PORTAL_ASSET_VERSION=${VCS_REF}
EXPOSE 8080
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "4", "--timeout", "120", "--access-logfile", "-", "--access-logformat", "%(h)s %(l)s %(u)s %(t)s \"%(m)s %(U)s %(H)s\" %(s)s %(b)s \"%(f)s\" \"%(a)s\"", "app.main:app"]
