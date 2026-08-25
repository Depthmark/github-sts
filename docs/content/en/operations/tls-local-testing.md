---
title: Testing TLS and mTLS locally
description: Step-by-step guide to generating a local PKI and smoke-testing HTTPS and mTLS against a running github-sts instance.
weight: 2
translationKey: tls-local-testing
---

This guide walks through creating a local certificate authority, signing a server certificate, starting github-sts over HTTPS, and then layering in mutual TLS (mTLS), all using `openssl` and `curl`. No real GitHub App credentials are needed to verify the TLS layer; the `/health` endpoint responds without authentication.

## Prerequisites

- `openssl` 1.1.1 or 3.x
- `curl` 7.77+ (for SNI and `--cert`/`--key` support)
- Go toolchain (to run `go run ./cmd/github-sts`) **or** Docker

## 1. Generate the local PKI

Run every command from the root of the repository. All files go into a `certs/` directory that you should not commit.

```bash
mkdir -p certs

# --- Certificate Authority ---
openssl genrsa -out certs/ca.key 4096
openssl req -new -x509 -key certs/ca.key -out certs/ca.crt -days 365 \
  -subj "/CN=github-sts-local-ca"

# --- Server certificate (must include SAN for modern TLS clients) ---
openssl genrsa -out certs/server.key 2048
openssl req -new -key certs/server.key -out certs/server.csr \
  -subj "/CN=localhost"
openssl x509 -req -in certs/server.csr \
  -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
  -out certs/server.crt -days 365 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

# --- RSA key for the github-sts App config (any valid RSA key) ---
openssl genrsa -out certs/app.key 2048
```

> `<(printf ...)` is bash/zsh process substitution. If your shell does not support it, write the SAN line to a temporary file and pass it with `-extfile /tmp/san.ext`.

## 2. Minimal configuration

Create `certs/config-tls.yaml`:

```yaml
server:
  port: 8443
  tls:
    cert_file: ./certs/server.crt
    key_file: ./certs/server.key

apps:
  local-test:
    app_id: 1
    private_key_path: ./certs/app.key

oidc:
  allowed_issuers:
    - https://token.actions.githubusercontent.com

audit:
  file_enabled: false   # default path /var/log/github-sts/audit.json won't exist locally
```

> `app_id: 1` and the RSA key are placeholders. They satisfy config validation but are never used when you only hit `/health`.

## 3. Start the server and test HTTPS

```bash
GITHUBSTS_CONFIG_PATH=certs/config-tls.yaml go run ./cmd/github-sts
```

The startup log will confirm TLS is active:

```
level=INFO msg="server ready" addr="0.0.0.0:8443" tls=true
```

In a second terminal, verify HTTPS using your CA:

```bash
curl --cacert certs/ca.crt https://localhost:8443/health
# {"status":"ok"}

curl --cacert certs/ca.crt https://localhost:8443/ready
# {"status":"ready"}
```

Verify that the server rejects connections that do not trust your CA:

```bash
curl https://localhost:8443/health
# curl: (60) SSL certificate problem: unable to get local issuer certificate
```

## 4. Add mTLS

### Generate a client certificate

```bash
openssl genrsa -out certs/client.key 2048
openssl req -new -key certs/client.key -out certs/client.csr \
  -subj "/CN=test-client"
openssl x509 -req -in certs/client.csr \
  -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
  -out certs/client.crt -days 365
```

### Enable mTLS in the config

Add `client_ca_file` to `certs/config-tls.yaml`:

```yaml
server:
  port: 8443
  tls:
    cert_file: ./certs/server.crt
    key_file: ./certs/server.key
    client_ca_file: ./certs/ca.crt   # trust the same CA for client certs
```

Restart the server.

### Test: client cert present (should succeed)

```bash
curl --cacert certs/ca.crt \
     --cert certs/client.crt \
     --key certs/client.key \
     https://localhost:8443/health
# {"status":"ok"}
```

### Test: client cert absent (should be rejected at the TLS layer)

```bash
curl --cacert certs/ca.crt https://localhost:8443/health
# curl: (35) error:... alert handshake failure
```

The connection is terminated during the TLS handshake, before any HTTP is exchanged.

## 5. Test hot-reload (optional)

Set `reload_interval` in the config and note the serial number of the certificate currently being served:

```yaml
server:
  tls:
    cert_file: ./certs/server.crt
    key_file: ./certs/server.key
    reload_interval: 5s
```

```bash
# Record the current serial
openssl s_client -connect localhost:8443 -CAfile certs/ca.crt </dev/null 2>/dev/null \
  | openssl x509 -noout -serial
# serial=01
```

Issue a new server certificate to the same file (the CA serial file `certs/ca.srl` auto-increments):

```bash
openssl x509 -req -in certs/server.csr \
  -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
  -out certs/server.crt -days 365 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")
```

Wait for the next poll tick (up to `reload_interval`). The server log will show:

```
level=INFO msg="tls cert reloaded"
```

Confirm the new certificate is being served:

```bash
openssl s_client -connect localhost:8443 -CAfile certs/ca.crt </dev/null 2>/dev/null \
  | openssl x509 -noout -serial
# serial=02
```

No connections were dropped and no restart was required.

## Cleanup

```bash
rm -rf certs/
```

The `certs/` directory contains your CA private key. Treat it as a secret: do not commit it, and delete it when you are done testing.
