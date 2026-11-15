FROM data.forgejo.org/forgejo/runner:13.2.1@sha256:568cea8c15ddc01fc8f330124892f572af7db37fa28344a2c1914405793bf61d

USER root
RUN apt-get update \
 && apt-get install --yes --no-install-recommends bash ca-certificates curl git jq \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

LABEL org.opencontainers.image.source="https://git.apps.d00s.org/infra/images" \
      org.opencontainers.image.description="Hardened Forgejo Actions runner with the tools used by d00s BuildKit workflows"

USER 1000:1000
