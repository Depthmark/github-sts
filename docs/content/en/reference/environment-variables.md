---
title: Environment Variables
description: All supported environment variables, valid values, defaults, and security notes.
weight: 3
translationKey: environment-variables
---

All variables use the `GITHUBSTS_` prefix. Per-app variables follow `GITHUBSTS_APP_{NAME}_{FIELD}`.

## Server settings

| Variable | Default | Description |
|---|---|---|
| `GITHUBSTS_CONFIG_PATH` | — | Path to YAML config file |
| `GITHUBSTS_SERVER_HOST` | `0.0.0.0` | HTTP listen host |
| `GITHUBSTS_SERVER_PORT` | `8080` | HTTP listen port |
| `GITHUBSTS_SERVER_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `GITHUBSTS_SERVER_SUPPRESS_HEALTH_LOGS` | `true` | Suppress health endpoint access logs |
| `GITHUBSTS_SERVER_SHUTDOWN_TIMEOUT` | `10s` | Graceful shutdown grace period |
| `GITHUBSTS_SERVER_TRUST_FORWARDED_HEADERS` | `false` | Trust `X-Forwarded-For` for client IP |
| `GITHUBSTS_SERVER_TLS_CERT_FILE` | — | Path to server certificate (PEM). HTTPS is enabled when both this and `_TLS_KEY_FILE` are set. |
| `GITHUBSTS_SERVER_TLS_KEY_FILE` | — | Path to server private key (PEM) |
| `GITHUBSTS_SERVER_TLS_CLIENT_CA_FILE` | — | Path to trusted client CA bundle (PEM). When set, client certificates are required and verified (mTLS). |
| `GITHUBSTS_SERVER_TLS_MIN_VERSION` | `1.2` | Minimum TLS version: `1.2` or `1.3`. |
| `GITHUBSTS_SERVER_TLS_CIPHER_SUITES` | — | Comma-separated TLS 1.2 cipher suite allowlist (IANA names). Empty = Go defaults. Ignored when `min_version` is `1.3`. |
| `GITHUBSTS_SERVER_TLS_RELOAD_INTERVAL` | `0` | Cert hot-reload poll interval (e.g. `1h`). `0` disables hot-reload. Requires cert and key to be set. |

## GitHub App settings

| Variable | Default | Description |
|---|---|---|
| `GITHUBSTS_APP_{NAME}_APP_ID` | *required* | GitHub App numeric ID |
| `GITHUBSTS_APP_{NAME}_PRIVATE_KEY` | *required* | PEM string (mutually exclusive with `_PATH`) |
| `GITHUBSTS_APP_{NAME}_PRIVATE_KEY_PATH` | — | Path to PEM file |
| `GITHUBSTS_APP_{NAME}_ORG_POLICY_REPO` | — | Repo for org-level policies (e.g. `.github`) |
| `GITHUBSTS_APP_{NAME}_POLICY_RESOLUTION` | `org_first` | Resolution mode: `org_first`, `repo_first` (deprecated), or `org_only` |
| `GITHUBSTS_APP_{NAME}_ROTATION_STRATEGY` | `round_robin` | Pool selection strategy: `round_robin` or `rate_limit_aware` (accepted, not yet implemented; see [Configuration]({{< relref "/reference/configuration#app-pools-multi-instance-rate-limit-rotation" >}})) |
| `GITHUBSTS_APP_{NAME}_ROTATION_MIN_REMAINING_PCT` | `0` | `rate_limit_aware` only; currently has no effect |
| `GITHUBSTS_APP_{NAME}_ROTATION_MAX_ATTEMPTS` | pool size, capped at `3` | Bound failover fan-out per request |

Individual pool instances (`apps.<name>.instances[N]` in YAML) can also be set or overridden per-instance, 1-based and contiguous: the loader stops at the first index `N` where none of the four variables below is set.

| Variable | Default | Description |
|---|---|---|
| `GITHUBSTS_APP_{NAME}_INSTANCE_{N}_APP_ID` | — | GitHub App numeric ID for pool instance `N` |
| `GITHUBSTS_APP_{NAME}_INSTANCE_{N}_PRIVATE_KEY` | — | PEM string for pool instance `N` (mutually exclusive with `_PATH`) |
| `GITHUBSTS_APP_{NAME}_INSTANCE_{N}_PRIVATE_KEY_PATH` | — | Path to PEM file for pool instance `N` |
| `GITHUBSTS_APP_{NAME}_INSTANCE_{N}_NAME` | `app_id` (stringified) | Metrics/audit label for pool instance `N` |

## Policy & security settings

| Variable | Default | Description |
|---|---|---|
| `GITHUBSTS_POLICY_BASE_PATH` | `.github/sts` | Base path in repos for trust policies |
| `GITHUBSTS_POLICY_CACHE_TTL` | `60s` | Policy cache TTL (`0` to disable) |
| `GITHUBSTS_OIDC_ALLOWED_ISSUERS` | — | Comma-separated issuer allowlist. Required; an empty list is a validation error. |
| `GITHUBSTS_OIDC_REQUIRED_AUDIENCE` | — | Server-wide required `aud` claim. When set, every token must carry this value (defense-in-depth on top of the per-policy `audience:` field). |
| `GITHUBSTS_JTI_BACKEND` | `memory` | `memory` or `redis` |
| `GITHUBSTS_JTI_REDIS_URL` | — | Redis connection URL (when backend=`redis`) |
| `GITHUBSTS_JTI_TTL` | `1h` | JTI replay protection window |

## Audit settings

| Variable | Default | Description |
|---|---|---|
| `GITHUBSTS_AUDIT_FILE_ENABLED` | `true` | Enable file-based audit logging |
| `GITHUBSTS_AUDIT_FILE_PATH` | `/var/log/github-sts/audit.json` | Audit log file path |
| `GITHUBSTS_AUDIT_BUFFER_SIZE` | `1024` | Audit channel buffer size |

## Metrics settings

| Variable | Default | Description |
|---|---|---|
| `GITHUBSTS_METRICS_ENABLED` | `true` | Enable Prometheus metrics |
| `GITHUBSTS_METRICS_AUTH_TOKEN` | — | Bearer token for the `/metrics` endpoint (empty = unauthenticated) |
| `GITHUBSTS_METRICS_RATE_LIMIT_POLL_ENABLED` | `true` | Poll `GET /rate_limit` periodically |
| `GITHUBSTS_METRICS_RATE_LIMIT_POLL_INTERVAL` | `60s` | Rate limit poll interval |
| `GITHUBSTS_METRICS_REACHABILITY_PROBE_ENABLED` | `true` | Probe GitHub API reachability |
| `GITHUBSTS_METRICS_REACHABILITY_PROBE_INTERVAL` | `30s` | Reachability probe interval |

## Rate limit settings

| Variable | Default | Description |
|---|---|---|
| `GITHUBSTS_RATE_LIMIT_ENABLED` | `false` | Enable per-IP rate limiting on `/sts/exchange` |
| `GITHUBSTS_RATE_LIMIT_RATE` | `10` | Requests per second per IP |
| `GITHUBSTS_RATE_LIMIT_BURST` | `20` | Maximum burst size per IP |
| `GITHUBSTS_RATE_LIMIT_EXEMPT_CIDRS` | — | CIDR ranges exempt from rate limiting |

## Security notes

- **Private keys:** Prefer `GITHUBSTS_APP_{NAME}_PRIVATE_KEY_PATH` over `_PRIVATE_KEY`. Environment variables appear in process listings and debug endpoints. Mount keys as files from a secret store.
- **Audience:** Set `GITHUBSTS_OIDC_REQUIRED_AUDIENCE` in production. This is defense-in-depth on top of the per-policy `audience:` field.
- **JTI backend:** Use `redis` for multi-replica deployments. The `memory` backend is per-instance and does not prevent cross-replica replay.
- **Issuer allowlist:** `GITHUBSTS_OIDC_ALLOWED_ISSUERS` is required. An empty list is a hard validation error, not an "accept any issuer" fallback.
- **TLS:** Native TLS is optional and activates only when both `GITHUBSTS_SERVER_TLS_CERT_FILE` and `GITHUBSTS_SERVER_TLS_KEY_FILE` are set. In Kubernetes, prefer TLS termination at the ingress/Gateway; use native TLS for standalone deployments or when re-encrypting Gateway→backend traffic. Setting `GITHUBSTS_SERVER_TLS_CLIENT_CA_FILE` enables mTLS and requires every client to present a certificate signed by that CA.
- **Cipher suites:** `GITHUBSTS_SERVER_TLS_CIPHER_SUITES` accepts IANA names (e.g. `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`). Only the non-insecure suites from Go's `tls.CipherSuites()` are valid. Unrecognised or insecure names are a validation error. Cipher suite selection is a TLS 1.2 concern only; when `min_version` is `1.3`, setting cipher suites is also a validation error.
- **Hot-reload:** When `GITHUBSTS_SERVER_TLS_RELOAD_INTERVAL` is set, github-sts polls the cert and key files for changes and reloads them without restarting. Without hot-reload, cert rotation requires a process restart.
