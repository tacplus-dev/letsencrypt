# LetsEncrypt Release Image
# Layers the letsencrypt binary onto a minimal Alpine base.

FROM registry.gitlab.com/secondstarcavalier/controlplane/containers/cavalier-alpine:latest

ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.authors="Second Star Cavalier LLC <cloudctlplane@secondstarcavalier.com>" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="Second Star Cavalier LLC" \
      org.opencontainers.image.title="LetsEncrypt" \
      org.opencontainers.image.description="ACME certificate management service for Cavalier control plane"

ARG TARGETARCH
RUN addgroup -S letsencrypt && adduser -S letsencrypt -G letsencrypt

COPY bin/letsencrypt-${TARGETARCH} /usr/local/bin/letsencrypt
RUN chmod +x /usr/local/bin/letsencrypt

USER letsencrypt

ENTRYPOINT ["letsencrypt"]
