# LetsEncrypt Release Image
# Layers the letsencrypt binary onto a minimal Alpine base.

FROM alpine:3.21

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

ARG GRPC_HEALTH_PROBE_VERSION=0.4.48
ARG TARGETARCH
RUN case "${TARGETARCH}" in amd64) GRPCURL_ARCH=x86_64;; *) GRPCURL_ARCH=${TARGETARCH};; esac && \
    apk add --no-cache ca-certificates tzdata \
    && wget -qO- "https://github.com/fullstorydev/grpcurl/releases/download/v1.9.3/grpcurl_1.9.3_linux_${GRPCURL_ARCH}.tar.gz" \
      | tar -xz -C /usr/local/bin grpcurl \
    && wget -qO /usr/local/bin/grpc_health_probe \
      "https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/v${GRPC_HEALTH_PROBE_VERSION}/grpc_health_probe-linux-${TARGETARCH}" \
    && chmod +x /usr/local/bin/grpc_health_probe \
    && addgroup -S letsencrypt && adduser -S letsencrypt -G letsencrypt

COPY bin/letsencrypt-${TARGETARCH} /usr/local/bin/letsencrypt
RUN chmod +x /usr/local/bin/letsencrypt

USER letsencrypt

ENTRYPOINT ["letsencrypt"]
