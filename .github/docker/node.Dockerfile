ARG NODE_VERSION=latest
FROM ghcr.io/pasarguard/node:${NODE_VERSION}
ARG TARGETARCH
COPY xray-${TARGETARCH} /usr/local/bin/xray
