FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S letsencrypt && adduser -S letsencrypt -G letsencrypt

WORKDIR /app

ARG TARGETARCH
COPY bin/letsencrypt-${TARGETARCH} /usr/bin/letsencrypt

USER letsencrypt

ENTRYPOINT ["letsencrypt"]
