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

## App pools (multi-instance rate-limit rotation)

A logical app name (`apps.<name>`) can be backed by a single GitHub App (`app_id` / `private_key` / `private_key_path`, as above) or by a pool of several physical GitHub Apps under `instances:`. Each instance has its own GitHub App credentials and therefore its own independent GitHub primary rate-limit bucket, so a pooled app's effective ceiling on `/sts/exchange` traffic scales with the number of instances. (This "instance" is a physical GitHub App, unrelated to a github-sts server replica; see [Architecture]({{< relref "/concepts/architecture#app-pools-and-failover" >}}).) Callers only ever see the logical app name in `?app=`; which instance served a given request is internal, and shows up only in the `instance` label on metrics and in the audit log (see [Metrics]({{< relref "/reference/metrics#app-pool-metrics" >}})).

```yaml
apps:
  checkout:
    org_policy_repo: ".github"
    instances:
      - name: checkout-1          # optional; defaults to app_id if omitted
        app_id: 111111
        private_key_path: "/etc/github-sts/keys/checkout-1.pem"
      - name: checkout-2
        app_id: 222222
        private_key_path: "/etc/github-sts/keys/checkout-2.pem"
      - name: checkout-3
        app_id: 333333
        private_key_path: "/etc/github-sts/keys/checkout-3.pem"
    rotation:
      strategy: round_robin        # round_robin (default) | rate_limit_aware
      min_remaining_pct: 5         # rate_limit_aware only
      max_attempts: 3              # bound failover fan-out per request
```

By default, github-sts round-robins across a pool's instances (a per-request cursor, so retries within one request walk consecutive members rather than re-randomizing), skips any instance the reachability prober currently reports down, and fails over to the next instance when the one it tried returns a retryable error. Retryable means a network/timeout error, a 5xx response, or a 403 that carries a rate-limit signal (`Retry-After` or `X-RateLimit-Remaining: 0`); a 422 (the requested permissions or repositories exceed what that installation grants) or any other 4xx is not retried, since trying a different credential cannot fix a permissions mismatch. `rotation.max_attempts` bounds how many instances one request will try (default: pool size, capped at 3).

Rules:

- `instances` and the flat `app_id` / `private_key` / `private_key_path` fields are mutually exclusive on one app. A flat-form app is treated as a pool of one.
- `rotation` is only meaningful on a pooled app (`instances` set): setting it on a flat-form app is a validation error, since it would otherwise be YAML that silently did nothing.
- Every instance needs `app_id` and exactly one of `private_key` / `private_key_path`.
- `app_id` must be unique **within** one app's pool. The same `app_id` reused across two different logical apps' pools is allowed (they already share a rate-limit bucket by construction) but logs a startup warning, since it's more often a copy-paste mistake than an intentional setup.
- `name` is optional and defaults to `app_id` (stringified). Because it becomes a Prometheus label value, it is limited to 100 characters from `[a-zA-Z0-9._/-]`.
- `rotation.strategy` is `round_robin` (default) or `rate_limit_aware`. **`rate_limit_aware` is accepted today but not yet implemented**: a pool configured with it behaves identically to `round_robin`, and github-sts logs a startup warning to that effect. It's reserved for a proactive-skip strategy that ranks instances by their last-observed remaining rate-limit percentage before making a request, rather than only reacting to a live failure.
- `rotation.min_remaining_pct` (range `[0, 100)`) only applies to `rate_limit_aware` and currently has no effect for the reason above.
- `rotation.max_attempts` defaults to `min(len(instances), 3)` when unset or `0`.

**Operational requirement:** every instance in a pool must be installed with identical permissions and repository access. github-sts treats pool members as interchangeable; it does not currently verify that they actually are, so a misconfigured instance surfaces only as an intermittent 422 or reachability failure on whichever fraction of requests happen to land on it.

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

See the [Trust Policies]({{< relref "/concepts/trust-policies" >}}) guide for the full policy schema, examples, and security guidance.
