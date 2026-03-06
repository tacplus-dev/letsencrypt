FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S letsencrypt && adduser -S letsencrypt -G letsencrypt

WORKDIR /app

COPY bin/letsencrypt /app/letsencrypt

USER letsencrypt

ENTRYPOINT ["/app/letsencrypt"]
