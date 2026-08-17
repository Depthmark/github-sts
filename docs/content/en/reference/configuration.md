---
title: Configuration
description: YAML configuration structure, default values, and complete reference.
weight: 2
translationKey: configuration
---

github-sts is configured through a YAML file, environment variables, or both. Environment variables override values from YAML, making YAML the source of truth for defaults and env vars the right place for secrets and per-environment overrides.

## YAML configuration

Point github-sts at a config file with `GITHUBSTS_CONFIG_PATH`:

```bash
export GITHUBSTS_CONFIG_PATH=/etc/github-sts/config.yaml
```

See [`config/github-sts.example.yaml`](https://github.com/Depthmark/github-sts/blob/main/config/github-sts.example.yaml) in the repo for a complete example.

A minimal config:

```yaml
server:
  port: 8080
  log_level: info

oidc:
  allowed_issuers:
    - https://token.actions.githubusercontent.com
  required_audience: https://sts.example.com

apps:
  default:
    app_id: 123456
    private_key_path: /etc/github-sts/keys/default.pem
    org_policy_repo: .github
    policy_resolution: org_first
```

Valid log levels are lowercase `debug | info | warn | error`. `oidc.allowed_issuers` must contain at least one issuer; an empty list is a validation error.

For production, deploy github-sts with the Helm chart rather than hand-managing this file. See [Deploy with Helm]({{< relref "/integrations/deploy-with-helm" >}}).

## Native TLS and mTLS

github-sts can serve HTTPS directly, but it does not manage certificate lifecycles. TLS is **implicitly enabled** when you provide both a certificate and a key; provide a client CA bundle to require and verify client certificates (mTLS):

```yaml
server:
  port: 8443
  tls:
    cert_file: /etc/github-sts/tls/tls.crt
    key_file: /etc/github-sts/tls/tls.key
    # Optional: enable mTLS by trusting a client CA bundle.
    # client_ca_file: /etc/github-sts/tls/client-ca.crt

    # Optional: enforce TLS 1.3 only (default: "1.2" — TLS 1.2 and above).
    # min_version: "1.3"

    # Optional: restrict to specific TLS 1.2 cipher suites (IANA names).
    # Omit to use Go's defaults. Cannot be set when min_version is "1.3".
    # cipher_suites:
    #   - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    #   - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    #   - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256

    # Optional: poll cert/key files on an interval and reload them when changed,
    # enabling zero-downtime certificate rotation. "0" disables polling (default).
    # Without this, cert rotation requires a process restart.
    # reload_interval: 1h
```

Rules:

- `cert_file` and `key_file` must be set together. Setting one without the other is a validation error.
- `client_ca_file` requires `cert_file` and `key_file`.
- `min_version` accepts `"1.2"` (default) or `"1.3"`. Minimum TLS version is TLS 1.2 when unset.
- `cipher_suites` accepts IANA cipher suite names. Only the non-insecure suites from Go's standard library are valid; unknown or weak names are a validation error. Setting cipher suites together with `min_version: "1.3"` is also a validation error — TLS 1.3 cipher suite selection is not configurable.
- `reload_interval` triggers interval-based polling of the cert and key files. When the files change, they are reloaded in-place without restarting the process. Requires `cert_file` and `key_file`.
- Client verification uses `RequireAndVerifyClientCert` when `client_ca_file` is set.

The recommended deployment model is to terminate TLS at the platform ingress/Gateway when available, and use native TLS for standalone deployments or when re-encrypting Gateway→backend traffic (e.g. Gateway API `BackendTLSPolicy`). See [Security Model]({{< relref "/concepts/security-model" >}}) for the trust-boundary guidance.

## Trust policies

Trust policies are YAML files stored **in the target repository** that define which OIDC identities can request tokens and with what permissions.

**Location:** `.github/sts/{app_name}/{identity}.sts.yaml`

The base path is configurable via `GITHUBSTS_POLICY_BASE_PATH` (default `.github/sts`).

See the [Trust Policies]({{< relref "/learn/trust-policies" >}}) guide for the full policy schema, examples, and security guidance.
