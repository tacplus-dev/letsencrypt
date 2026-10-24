# LetsEncrypt Release Image
# Layers the letsencrypt binary onto a minimal Alpine base.

# The base is a build argument: a fleet may hand in its own hardened base, the
# default is the public one (no private registry in a public contract's repo).
ARG BASE_IMAGE=alpine:3.22
FROM ${BASE_IMAGE}

ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.authors="Seabeam LLC <cloudctlplane@seabeam.com>" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="Seabeam LLC" \
      org.opencontainers.image.title="LetsEncrypt" \
      org.opencontainers.image.description="ACME certificate management service for Schematic control plane"

RUN apk add --no-cache ca-certificates
COPY bin/letsencrypt /usr/local/bin/letsencrypt

# Every service runs under the launcher (github.com/tacplus-dev/launcher): PID 1
# that forwards signals, propagates the exit code, and kills a deadlocked child
# on gRPC health. The fleet's image pipeline puts the binary beside the Dockerfile.
ARG TARGETARCH
COPY launcher-linux-${TARGETARCH} /usr/local/bin/launcher
ENV LAUNCH_CMD="letsencrypt" HEALTH_PORT=8443
ENTRYPOINT ["launcher"]
