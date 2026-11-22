FROM data.forgejo.org/forgejo/runner:13.2.2@sha256:a8543a45fe62bebef0534d5c223cf485d3294e6dd2e42a82dbcbfd40c54a6a22

USER root
RUN apk upgrade --no-cache && apk add --no-cache bash ca-certificates curl git jq nodejs npm

LABEL org.opencontainers.image.source="https://git.apps.d00s.org/infra/images" \
      org.opencontainers.image.description="Hardened Forgejo Actions runner with the tools used by d00s BuildKit workflows"

USER 1000:1000