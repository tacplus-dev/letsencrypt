# LetsEncrypt

LetsEncrypt obtains TLS certificates from Let's Encrypt via the ACME protocol
and stores them in kernel's Identity state. It periodically checks for
certificate expiry and handles automatic renewal. Only needed when using
Let's Encrypt for certificate management.

## Architecture

LetsEncrypt reads its configuration from a local config file (not from kernel),
connects to kernel via the tacplus ServiceManager, and writes obtained
certificates to kernel's Identity state. It imports `kernel.Identity` state
for certificate storage.

## Configuration

| Field | Default | Description |
|-------|---------|-------------|
| `lets_encrypt_email` | — | Email for Let's Encrypt account registration |
| `http_listener` | 0.0.0.0:80 | HTTP listener for ACME HTTP-01 challenges |
| `renewal_check_interval_seconds` | 3600 | How often to check for expiring certs |
| `fqdn` | — | Fully qualified domain name for the certificate (required) |

## Build

```bash
just        # generate + compile
```

## Proto

[`services/letsencrypt.proto`](../../proto/services/letsencrypt.proto)
