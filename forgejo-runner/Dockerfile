FROM data.forgejo.org/forgejo/runner:13.2.1@sha256:568cea8c15ddc01fc8f330124892f572af7db37fa28344a2c1914405793bf61d

USER root
RUN apk upgrade --no-cache && apk add --no-cache bash ca-certificates curl git jq nodejs npm

LABEL org.opencontainers.image.source="https://git.apps.d00s.org/infra/images" \
      org.opencontainers.image.description="Hardened Forgejo Actions runner with the tools used by d00s BuildKit workflows"

USER 1000:1000
