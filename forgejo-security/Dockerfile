FROM code.forgejo.org/forgejo/forgejo:15.0.11-rootless@sha256:ab0b8fd8bfc55b6e0721347c0173c128c6431b3543ff2ab7a863929f1c5d2629

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
      org.opencontainers.image.source="https://github.com/edwardtls/images" \
      org.opencontainers.image.title="Forgejo security-patched runtime"

USER 1000:1000
