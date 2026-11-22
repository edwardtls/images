FROM code.forgejo.org/forgejo/forgejo:15.0.12-rootless@sha256:b670d7724274e1d5c7801b76017b7267e6e5432aa4fe8bed49f781d09476b9dd

ARG BUILD_DATE
ARG VCS_REF

USER root

# Forgejo 15.0.11 was published before Alpine shipped the OpenSSH fix for
# CVE-2026-123158. Keep the upstream application and entrypoint unchanged and
# update only the affected runtime packages from the same Alpine 3.23 branch.
RUN apk upgrade --no-cache \
      openssh-client-common \
      openssh-client-default \
      openssh-keygen \
    && apk audit --no-cache

LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://git.apps.d00s.org/infra/images" \
      org.opencontainers.image.title="Forgejo security-patched runtime"

USER 1000:1000