# Deployment

## Docker

The official image is built from a [distroless](https://github.com/GoogleContainerTools/distroless) base with a nonroot user for a minimal attack surface.

```bash
# Build
docker build -t github-sts:local .

# Run with config file
docker run -p 8080:8080 \
  -v /path/to/github-sts.yaml:/etc/github-sts/config.yaml:ro \
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
mount a config with `bundle_enforcement: required` and a pinned, verified global
baseline.

## Helm / Kubernetes

A Helm chart is maintained in a separate repository: [github-sts-helm](https://github.com/Depthmark/github-sts-helm).

See the chart repo for installation instructions, Ingress/HTTPRoute setup, and full `values.yaml` reference.

A typical production deployment supplies a reviewed values file that renders
the required bundle contract:

```bash
helm repo add depthmark https://depthmark.github.io/charts
helm install github-sts depthmark/github-sts \
  --namespace github-sts --create-namespace \
  --values /path/to/production-values.yaml
```

The rendered server config must include `bundle_enforcement: required`, exactly
one global `apps: []` baseline, and its digest-pinned OCI/cosign settings. Exact
chart values keys may evolve; check the chart repo's `values.yaml` for the
authoritative mapping.

### Immutable subject rollout

For a repository still using GitHub's legacy subject format, coordinate these
steps to avoid locking out its workflow:

1. Record the immutable owner and repository IDs.
2. Opt the repository in to immutable subject claims in GitHub.
3. Confirm a newly minted token contains the expected IDs in `sub`,
   `repository_owner_id`, and `repository_id`.
4. Update its target trust policies to the immutable subject.
5. Deploy the default-on broker configuration.

The checked-in `Depthmark/github-sts` release policy now expects owner ID
`268749784` and repository ID `1198676434`. Opt that repository in before
merging the policy migration. The legacy server opt-out does not make an exact
immutable trust policy match a legacy token.

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
- [ ] Every bundle is cosign verified with keyless signer/issuer constraints for `Depthmark/github-sts-policy` or an explicitly managed `public_key_ref`; verification is never skipped.
- [ ] The mandatory baseline passes the fixed `sts.enterprise.v1` metadata and negative-probe admission contract before rollout.
- [ ] Alerts are configured for bundle pull failures, stale bundles, policy revision changes, and expiring exceptions.
- [ ] TLS terminates at an ingress/sidecar — github-sts itself listens on plain HTTP.
- [ ] Rate limits and request size limits are configured at the ingress layer.

## Observability

All metrics are exposed at `GET /metrics` in Prometheus text format with the `githubsts_` prefix.

Check `/health.security.bundle_enforcement`, `enterprise_policy_required`, and
`yaml_only_authorization` after every rollout. Each configured `bundles[]`
status reports `mandatory` and the admitted `policy_revision` alongside digest,
age, enabled state, and pull errors. Health remains liveness-only even when an
exchange would fail closed.

Exchange audit events include `bundle_enforcement`. Once the bundle path is
reached, they add `bundle_digest` and `org_decision.applicable` /
`org_decision.evaluated`; completed evaluations add `bundle_decisions`.
Preserve these fields in the SIEM so an evaluated `403 org_policy_denied`
remains distinguishable from the bundle-related `503` errors.

| Metric | Type | Description |
|---|---|---|
| `githubsts_http_requests_total` | Counter | HTTP requests by method, path, status |
| `githubsts_oidc_immutable_subject_claims_required` | Gauge | `1` when immutable GitHub.com subjects are required; `0` when the visible legacy opt-out is active. |
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
| `githubsts_bundle_enforcement_required` | Gauge | `1` in required mode; `0` in explicitly optional mode |
| `githubsts_org_decision_total` | Counter | Enterprise Rego outcomes by app, bundle, and result (`allow`, `deny`, `error`, or `not_evaluated`) |
| `githubsts_bundle_pull_total` | Counter | Bundle pull attempts by bundle and result |
| `githubsts_bundle_verify_total` | Counter | Cosign verification attempts by bundle and result (`success`, `failure`, or explicit `skipped`) |
| `githubsts_bundle_loaded_digest_info` | Gauge | Current loaded bundle digest by bundle |
| `githubsts_bundle_age_seconds` | Gauge | Seconds since last successful bundle pull by bundle |
| `githubsts_bundle_reload_total` | Counter | Bundle reload attempts by bundle and result |
| `githubsts_bundle_stale_evals_total` | Counter | Exchanges evaluated with stale bundles by bundle and fail mode |
| `githubsts_bundle_policy_revision_info` | Gauge | Active Rego policy digest by bundle |
| `githubsts_bundle_policy_revision_changes_total` | Counter | Policy revision reload outcomes by bundle |
| `githubsts_bundle_policy_decisions_total` | Counter | Aggregate Rego decision impact by app, bundle, digest, and result |
| `githubsts_bundle_policy_rule_decisions_total` | Counter | Rego decisions by bounded enterprise rule ID |
| `githubsts_bundle_policy_exceptions_total` | Gauge | Discovered exception inventory by bundle, digest, and status |
| `githubsts_bundle_policy_exception_expiration_timestamp_seconds` | Gauge | Exception expiration timestamp by bundle, digest, exception ID, rule ID, and owner |
| `githubsts_bundle_policy_exception_seconds_until_expiration` | Gauge | Seconds until exception expiration by bundle, digest, exception ID, rule ID, and owner |
| `githubsts_bundle_policy_exception_hits_total` | Counter | Exchanges where a Rego decision reported an exception hit |

### Recommended alerts

- `rate(githubsts_oidc_validation_errors_total[5m]) > 0` for sustained periods — possible misconfiguration or attack.
- `rate(githubsts_jti_replay_attempts_total[5m]) > 0` — investigate immediately.
- `githubsts_github_reachable == 0` — github-sts cannot reach GitHub; tokens will fail.
- `githubsts_bundle_enforcement_required == 0` — deployment is running in explicitly optional enterprise-policy posture.
- `rate(githubsts_bundle_pull_total{result="failure"}[5m]) > 0` — bundle pull is failing.
- `rate(githubsts_bundle_verify_total{result="failure"}[5m]) > 0` — bundle signature verification is failing.
- `githubsts_bundle_age_seconds > max_staleness_seconds` — bundle is stale; fail-closed bundles return `503 bundle_stale`.
- `increase(githubsts_bundle_policy_revision_changes_total{result="changed"}[10m]) > 0` — active Rego revision changed; review decision impact metrics.
- `githubsts_bundle_policy_exception_seconds_until_expiration < 604800` — exception expires in less than seven days.
- `githubsts_bundle_policy_exceptions_total{status="expired"} > 0` — expired exceptions remain in the loaded bundle.
- `rate(githubsts_audit_events_dropped_total[5m]) > 0` — increase `GITHUBSTS_AUDIT_BUFFER_SIZE` or audit sink throughput.
- `histogram_quantile(0.99, githubsts_token_exchange_duration_seconds) > 1` — exchange latency regression.
