# Deployment

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

## Helm / Kubernetes

A Helm chart is maintained in a separate repository: [github-sts-helm](https://github.com/Depthmark/github-sts-helm).

See the chart repo for installation instructions, Ingress/HTTPRoute setup, and full `values.yaml` reference.

A typical deployment looks like:

```bash
helm repo add depthmark https://depthmark.github.io/charts
helm install github-sts depthmark/github-sts \
  --namespace github-sts --create-namespace \
  --set apps.default.appId=123456 \
  --set-file apps.default.privateKey=/path/to/private-key.pem \
  --set oidc.requiredAudience=https://sts.example.com
```

> **Note:** Exact values keys may evolve — always check the chart repo's `values.yaml` for the authoritative reference.

## Production checklist

Before exposing github-sts publicly:

- [ ] `oidc.allowed_issuers` is set to the explicit list of issuers you accept.
- [ ] `oidc.required_audience` is set to a value unique to this STS deployment (e.g. `https://sts.example.com`). Each trust policy's `audience:` matches it.
- [ ] `jti.backend` is `redis` if you run more than one replica.
- [ ] GitHub App private keys are mounted from a secret store (Kubernetes Secret, Vault, cloud KMS), **not** baked into images or env files.
- [ ] `/health` and `/ready` are wired to liveness/readiness probes.
- [ ] `/metrics` is scraped by Prometheus and dashboards are in place.
- [ ] Audit log is written to a persistent location and forwarded to your SIEM.
- [ ] TLS terminates at an ingress/sidecar — github-sts itself listens on plain HTTP.
- [ ] Rate limits and request size limits are configured at the ingress layer.

## Observability

All metrics are exposed at `GET /metrics` in Prometheus text format with the `githubsts_` prefix.

| Metric | Type | Description |
|---|---|---|
| `githubsts_http_requests_total` | Counter | HTTP requests by method, path, status |
| `githubsts_http_request_duration_seconds` | Histogram | HTTP request latency |
| `githubsts_http_requests_in_flight` | Gauge | Concurrent requests |
| `githubsts_token_exchanges_total` | Counter | Exchange attempts by app, scope, identity, result |
| `githubsts_token_exchange_duration_seconds` | Histogram | Exchange latency |
| `githubsts_oidc_validation_errors_total` | Counter | OIDC failures by issuer, reason |
| `githubsts_policy_loads_total` | Counter | Policy loads by app, backend, result |
| `githubsts_policy_cache_hits_total` | Counter | Cache hits by app |
| `githubsts_policy_cache_misses_total` | Counter | Cache misses by app |
| `githubsts_github_api_calls_total` | Counter | GitHub API calls by app, endpoint, result |
| `githubsts_github_tokens_issued_total` | Counter | Tokens issued by app, scope, permissions |
| `githubsts_github_rate_limit_remaining` | Gauge | Remaining GitHub rate limit by app, resource |
| `githubsts_github_reachable` | Gauge | GitHub API reachability (1/0) by app |
| `githubsts_jti_replay_attempts_total` | Counter | JTI replay attacks detected |
| `githubsts_audit_events_dropped_total` | Counter | Audit events dropped (full buffer) |
| `githubsts_ready` | Gauge | Instance readiness (1/0) |

### Recommended alerts

- `rate(githubsts_oidc_validation_errors_total[5m]) > 0` for sustained periods — possible misconfiguration or attack.
- `rate(githubsts_jti_replay_attempts_total[5m]) > 0` — investigate immediately.
- `githubsts_github_reachable == 0` — github-sts cannot reach GitHub; tokens will fail.
- `rate(githubsts_audit_events_dropped_total[5m]) > 0` — increase `GITHUBSTS_AUDIT_BUFFER_SIZE` or audit sink throughput.
- `histogram_quantile(0.99, githubsts_token_exchange_duration_seconds) > 1` — exchange latency regression.
