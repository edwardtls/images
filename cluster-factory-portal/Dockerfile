FROM python:3.13.9-alpine3.22@sha256:e5fa639e49b85986c4481e28faa2564b45aa8021413f31026c3856e5911618b1

RUN apk add --no-cache openssh-client ca-certificates tini \
    && addgroup -g 65532 portal \
    && adduser -D -u 65532 -G portal -h /app portal

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --requirement /app/requirements.txt
COPY app /app/app
RUN chown -R 65532:65532 /app

USER 65532:65532
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
EXPOSE 8080
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "4", "--timeout", "120", "--access-logfile", "-", "app.main:app"]
