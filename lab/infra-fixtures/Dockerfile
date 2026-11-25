FROM node:25-bookworm@sha256:78839ac448c23517f8eab2e8f7943d9b4f73979eb7f8bed2c73dbf72ff869e7b AS node
FROM python@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7
ARG LAB_RECIPE_SHA256
LABEL org.amqic.infra.recipe-sha256=$LAB_RECIPE_SHA256
# Signed, date-frozen Debian repositories; versions are also recorded at runtime.
RUN . /etc/os-release && test "$VERSION_CODENAME" = bookworm && rm -f /etc/apt/sources.list.d/debian.sources && \
    printf 'Types: deb\nURIs: https://snapshot.debian.org/archive/debian/20261113T000000Z\nSuites: bookworm\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\nCheck-Valid-Until: no\n\nTypes: deb\nURIs: https://snapshot.debian.org/archive/debian-security/20261113T000000Z\nSuites: bookworm-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\nCheck-Valid-Until: no\n' > /etc/apt/sources.list.d/debian.sources && \
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      openssh-server openssh-client nftables iproute2 wireguard-tools iputils-ping python3 gcc libc6-dev binutils keepassxc && \
    rm -rf /var/lib/apt/lists/*
COPY --from=node /usr/local/bin/node /usr/local/bin/node
CMD ["sleep", "infinity"]
