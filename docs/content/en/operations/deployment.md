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

## Production checklist

Before exposing github-sts publicly:

- [ ] `oidc.allowed_issuers` is set to the explicit list of issuers you accept.
- [ ] `oidc.required_audience` is set to a value unique to this STS deployment (e.g. `https://sts.example.com`). Each trust policy's `audience:` matches it.
- [ ] `jti.backend` is `redis` if you run more than one replica.
- [ ] GitHub App private keys are mounted from a secret store (Kubernetes Secret, Vault, cloud KMS), **not** baked into images or env files.
- [ ] `/health` and `/ready` are wired to liveness/readiness probes.
- [ ] `/metrics` is scraped by Prometheus and dashboards are in place.
- [ ] Audit log is written to a persistent location and forwarded to your SIEM.
- [ ] TLS terminates at an ingress/sidecar: github-sts itself listens on plain HTTP.
- [ ] Rate limits and request size limits are configured at the ingress layer.
