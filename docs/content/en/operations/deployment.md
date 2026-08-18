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

# Run with env vars only (explicit YAML-only development posture)
docker run -p 8080:8080 \
  -e GITHUBSTS_CONFIG_PATH=/dev/null \
  -e GITHUBSTS_APP_DEFAULT_APP_ID="$GITHUBSTS_APP_DEFAULT_APP_ID" \
  -e GITHUBSTS_APP_DEFAULT_PRIVATE_KEY="$GITHUBSTS_APP_DEFAULT_PRIVATE_KEY" \
  -e GITHUBSTS_OIDC_ALLOWED_ISSUERS="https://token.actions.githubusercontent.com" \
  -e GITHUBSTS_OIDC_REQUIRED_AUDIENCE="https://sts.example.com" \
  -e GITHUBSTS_OIDC_REQUIRE_IMMUTABLE_SUBJECT_CLAIMS="true" \
  -e GITHUBSTS_BUNDLE_ENFORCEMENT="optional" \
  github-sts:local
```

The env-only example intentionally has no enterprise bundle. It emits the
optional/YAML-only warning and posture signals. Production deployments should
mount a config with `bundle_enforcement: required` and a pinned, verified
global baseline — see [Enterprise Rego bundles]({{< relref "/reference/configuration#enterprise-rego-bundles" >}}).

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
- [ ] GitHub.com repositories have opted in to immutable subject claims and trust policies contain exact `github.sources[]` and `github.target` IDs. Keep `oidc.require_immutable_subject_claims: true`.
- [ ] `jti.backend` is `redis` if you run more than one replica.
- [ ] GitHub App private keys are mounted from a secret store (Kubernetes Secret, Vault, cloud KMS), **not** baked into images or env files.
- [ ] `/health` and `/ready` are wired to liveness/readiness probes.
- [ ] `/metrics` is scraped by Prometheus and dashboards are in place.
- [ ] Audit log is written to a persistent location and forwarded to your SIEM.
- [ ] Top-level `bundle_enforcement` is `required`; the `GITHUBSTS_BUNDLE_ENFORCEMENT` override cannot downgrade production unexpectedly.
- [ ] Exactly one global baseline has `apps: []` and `fail_mode: closed`; app-scoped bundles are additive.
- [ ] Every bundle ref is trusted OCI pinned to `@sha256:<64 lowercase hex>`. File refs and mutable tags are not used.
- [ ] Every bundle has a canonical `expected_policy_revision` matching its signed `.manifest.revision`; mandatory Rego metadata matches it too.
- [ ] Policy release and deployment CI reject lower revisions and reused revision/digest values using a protected current tuple.
- [ ] Every bundle is cosign verified with keyless signer/issuer constraints for `Depthmark/github-sts-policy` or an explicitly managed `public_key_ref`; verification is never skipped.
- [ ] The mandatory baseline passes the fixed `sts.enterprise.v1` metadata and negative-probe admission contract before rollout.
- [ ] Alerts are configured for bundle pull failures, stale bundles, policy revision changes, and expiring exceptions.
- [ ] TLS terminates at an ingress/Gateway, or native TLS/mTLS is enabled with **CA-issued** certificates (never self-signed in production).
- [ ] Rate limits and request size limits are configured at the ingress layer.
