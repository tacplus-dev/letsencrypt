# LetsEncrypt Release Image
# Layers the letsencrypt binary onto a minimal Alpine base.

FROM registry.gitlab.com/secondstarcavalier/schematic/containers/alpine/schematic-alpine-1-2:latest

ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.authors="Second Star Cavalier LLC <cloudctlplane@secondstarcavalier.com>" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="Second Star Cavalier LLC" \
      org.opencontainers.image.title="LetsEncrypt" \
      org.opencontainers.image.description="ACME certificate management service for Schematic control plane"

COPY bin/letsencrypt /usr/local/bin/letsencrypt

ENTRYPOINT ["letsencrypt"]
