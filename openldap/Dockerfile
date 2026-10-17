FROM debian:13-slim AS builder

ARG OPENLDAP_VERSION=2.6.15
ARG OPENLDAP_SHA3_512=77627844339d7a23e80f24a1aa95cbd5c919d9b17066b1ab506322dc1787415817cf0509c7b4fe44670cc643ad61c19395b650f01802d6dd7f73e865dc70d97a

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        groff-base \
        libargon2-dev \
        libevent-dev \
        libltdl-dev \
        libsasl2-dev \
        libssl-dev \
        libtool \
    && curl --fail --show-error --location \
        --output /tmp/openldap.tgz \
        "https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-${OPENLDAP_VERSION}.tgz" \
    && test "$(openssl dgst -sha3-512 /tmp/openldap.tgz | awk '{print $2}')" \
        = "${OPENLDAP_SHA3_512}" \
    && tar --extract --gzip --file /tmp/openldap.tgz --directory /tmp \
    && cd "/tmp/openldap-${OPENLDAP_VERSION}" \
    && ./configure \
        --prefix=/opt/openldap \
        --sysconfdir=/etc/openldap \
        --localstatedir=/var \
        --enable-dynamic \
        --enable-modules \
        --enable-mdb=mod \
        --enable-memberof=mod \
        --enable-ppolicy=mod \
        --enable-syncprov=mod \
        --enable-argon2=yes \
        --with-cyrus-sasl \
        --with-tls=openssl \
    && make depend \
    && make --jobs="$(nproc)" \
    && make install \
    && /opt/openldap/sbin/slapd -VV \
    && /opt/openldap/sbin/slappasswd -h '{ARGON2}' -s image-build-check >/dev/null

FROM debian:13-slim

ARG OPENLDAP_VERSION=2.6.15

LABEL org.opencontainers.image.source="https://github.com/edwardtls/images"
LABEL org.opencontainers.image.description="Minimal non-root OpenLDAP ${OPENLDAP_VERSION} LTS runtime"
LABEL org.opencontainers.image.version="${OPENLDAP_VERSION}"

RUN apt-get update \
    && apt-get upgrade --yes \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        libargon2-1 \
        libevent-2.1-7t64 \
        libltdl7 \
        libsasl2-2 \
        libssl3t64 \
        tini \
    && groupadd --gid 10001 ldap \
    && useradd --uid 10001 --gid 10001 --home-dir /var/lib/openldap --no-create-home --shell /usr/sbin/nologin ldap \
    && install --directory --owner=10001 --group=10001 --mode=0700 \
        /var/lib/openldap /run/openldap \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/openldap /opt/openldap

ENV PATH="/opt/openldap/bin:/opt/openldap/sbin:${PATH}"

USER 10001:10001
WORKDIR /var/lib/openldap
EXPOSE 1389 1636

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/opt/openldap/libexec/slapd", "-d", "0", "-f", "/run/openldap/slapd.conf", "-h", "ldap://0.0.0.0:1389 ldaps://0.0.0.0:1636"]
