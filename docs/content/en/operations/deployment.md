---
title: Deployment
description: Docker deployment and production checklist for github-sts.
weight: 1
translationKey: deployment
---

github-sts can be deployed with Docker (this page) or with the Helm chart on Kubernetes. For Kubernetes, see [Kubernetes]({{< relref "/operations/kubernetes" >}}).

## Docker

The official image is built from a [distroless](https://github.com/GoogleContainerTools/distroless) base with a nonroot user for a minimal attack surface.

```bash
# Build
docker build -t github-sts:local .

# Run with config file
docker run -p 8080:8080 \
  -v $(pwd)/config/github-sts.example.yaml:/etc/github-sts/config.yaml:ro \
  -e GITHUBSTS_CONFIG_PATH=/etc/github-sts/config.yaml \
  -e GITHUBSTS_APP_DEFAULT_APP_ID="$GITHUBSTS_APP_DEFAULT_APP_ID" \
  -e GITHUBSTS_APP_DEFAULT_PRIVATE_KEY="$GITHUBSTS_APP_DEFAULT_PRIVATE_KEY" \
  github-sts:local

# Run with env vars only
docker run -p 8080:8080 \
  -e GITHUBSTS_CONFIG_PATH=/dev/null \
  -e GITHUBSTS_APP_DEFAULT_APP_ID="$GITHUBSTS_APP_DEFAULT_APP_ID" \
  -e GITHUBSTS_APP_DEFAULT_PRIVATE_KEY="$GITHUBSTS_APP_DEFAULT_PRIVATE_KEY" \
  -e GITHUBSTS_OIDC_ALLOWED_ISSUERS="https://token.actions.githubusercontent.com" \
  -e GITHUBSTS_OIDC_REQUIRED_AUDIENCE="https://sts.example.com" \
  github-sts:local
```

## TLS and mTLS

github-sts supports native HTTPS and mTLS, but does not manage certificates. TLS is enabled implicitly when both a certificate and a key are supplied; add a client CA bundle to require client certificates.

```yaml
server:
  host: "0.0.0.0"
  port: 8443
  tls:
    cert_file: /etc/github-sts/tls/tls.crt
    key_file: /etc/github-sts/tls/tls.key
    # client_ca_file: /etc/github-sts/tls/ca.crt   # optional mTLS
```

Run it by mounting the certificate and key read-only (the container runs as a nonroot user, so the files must be readable by it):

```bash
docker run -p 8443:8443 \
  -v $(pwd)/config/github-sts.example.yaml:/etc/github-sts/config.yaml:ro \
  -v $(pwd)/certs:/etc/github-sts/tls:ro \
  -e GITHUBSTS_CONFIG_PATH=/etc/github-sts/config.yaml \
  github-sts:local
```

> **Warning — self-signed certificates are for local development only.** In production, obtain certificates from a trusted CA — `cert-manager`/Let's Encrypt, your internal PKI, or a managed service such as AWS ACM or Azure Key Vault — and terminate TLS at the ingress/Gateway where possible.

For a complete walkthrough — including generating a local CA, signing server and client certificates, and verifying HTTPS and mTLS rejection with `curl` — see [Testing TLS and mTLS locally]({{< relref "/operations/tls-local-testing" >}}).

See [Configuration]({{< relref "/reference/configuration" >}}) for the full TLS option reference.

## Production checklist

Before exposing github-sts publicly:

- [ ] `oidc.allowed_issuers` is set to the explicit list of issuers you accept.
- [ ] `oidc.required_audience` is set to a value unique to this STS deployment (e.g. `https://sts.example.com`). Each trust policy's `audience:` matches it.
- [ ] `jti.backend` is `redis` if you run more than one replica.
- [ ] GitHub App private keys are mounted from a secret store (Kubernetes Secret, Vault, cloud KMS), **not** baked into images or env files.
- [ ] `/health` and `/ready` are wired to liveness/readiness probes.
- [ ] `/metrics` is scraped by Prometheus and dashboards are in place.
- [ ] Audit log is written to a persistent location and forwarded to your SIEM.
- [ ] TLS terminates at an ingress/Gateway, or native TLS/mTLS is enabled with **CA-issued** certificates (never self-signed in production).
- [ ] Rate limits and request size limits are configured at the ingress layer.
