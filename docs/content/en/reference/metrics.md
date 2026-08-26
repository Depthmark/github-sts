---
title: Metrics
description: Prometheus metric names, types, labels, operational meaning, and recommended alert queries.
weight: 4
translationKey: metrics
---

All metrics are exposed at `GET /metrics` in Prometheus text format with the `githubsts_` prefix.

**Upgrading from a version without app pools?** Every GitHub App, rate-limit, and reachability metric below now carries an additional `instance` label — see [Migration: pool metrics `instance` label]({{< relref "/operations/upgrades#migration-pool-metrics-instance-label" >}}) for the affected metric list, before/after PromQL, and a step-by-step checklist.

## Authenticate scrapes

Bearer shared-secret authentication is the only authentication method specific to `GET /metrics`. Set `GITHUBSTS_METRICS_AUTH_TOKEN` to enable it:

```bash
export GITHUBSTS_METRICS_AUTH_TOKEN="replace-with-a-random-secret"
```

This example assumes github-sts serves HTTPS on port 8443 with a certificate trusted by the Prometheus host. See [Native TLS and mTLS]({{< relref "/reference/configuration" >}}) for server setup.

Configure the Prometheus scrape job with the same token. Prefer a file mounted from your secret manager instead of storing the token directly in `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: github-sts
    scheme: https
    static_configs:
      - targets: ["github-sts:8443"]
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/secrets/github-sts-metrics-token
    tls_config:
      ca_file: /etc/prometheus/certs/github-sts-ca.crt
```

The credentials file must contain only the token value. When the setting is non-empty, verify that a request without the token returns `401` and a request with the token returns `200`:

```bash
curl --cacert /path/to/github-sts-ca.crt -o /dev/null -s -w '%{http_code}\n' \
  https://github-sts:8443/metrics
# 401

curl --cacert /path/to/github-sts-ca.crt -o /dev/null -s -w '%{http_code}\n' \
  -H "Authorization: Bearer $GITHUBSTS_METRICS_AUTH_TOKEN" \
  https://github-sts:8443/metrics
# 200
```

When the setting is empty, the endpoint remains unauthenticated. HTTPS protects the Bearer token in transit but does not authenticate the scraper. Native mTLS can authenticate clients for the entire server, including `/health` and `/ready`. A reverse proxy or service mesh can provide other authentication methods outside github-sts.

## HTTP metrics

| Metric | Type | Description |
|---|---|---|
| `githubsts_http_requests_total` | Counter | HTTP requests by method, path, status |
| `githubsts_oidc_immutable_subject_claims_required` | Gauge | `1` when immutable GitHub.com subjects are required; `0` when the visible legacy opt-out is active. |
| `githubsts_http_request_duration_seconds` | Histogram | HTTP request latency |
| `githubsts_http_requests_in_flight` | Gauge | Concurrent requests |

## Token exchange metrics

| Metric | Type | Description |
|---|---|---|
| `githubsts_token_exchanges_total` | Counter | Exchange attempts by app, instance, scope, identity, issuer, result |
| `githubsts_token_exchange_duration_seconds` | Histogram | Exchange latency by app, instance, scope, identity, issuer |
| `githubsts_oidc_validation_errors_total` | Counter | OIDC failures by issuer, reason |

## JTI replay prevention

| Metric | Type | Description |
|---|---|---|
| `githubsts_jti_replay_attempts_total` | Counter | JTI replay attacks detected |
| `githubsts_jti_cache_errors_total` | Counter | JTI cache operation errors by error_type |

## Policy metrics

| Metric | Type | Description |
|---|---|---|
| `githubsts_policy_loads_total` | Counter | Policy loads by app, backend, result |
| `githubsts_policy_cache_hits_total` | Counter | Cache hits by app |
| `githubsts_policy_cache_misses_total` | Counter | Cache misses by app |

## GitHub API metrics

| Metric | Type | Description |
|---|---|---|
| `githubsts_github_api_calls_total` | Counter | GitHub API calls by app, instance, endpoint, result |
| `githubsts_github_tokens_issued_total` | Counter | Tokens issued by app, instance, scope, permissions |
| `githubsts_github_rate_limit_remaining` | Gauge | Remaining rate limit by app, instance, resource |
| `githubsts_github_rate_limit_limit` | Gauge | Maximum requests allowed in current window, by app, instance, resource |
| `githubsts_github_rate_limit_used` | Gauge | Requests used in current window, by app, instance, resource |
| `githubsts_github_rate_limit_reset_timestamp` | Gauge | Unix epoch timestamp when window resets, by app, instance, resource |
| `githubsts_github_rate_limit_remaining_percent` | Gauge | Percentage of rate limit remaining, by app, instance, resource |
| `githubsts_github_rate_limit_exceeded_total` | Counter | Primary rate limit exceeded events, by app, instance, resource, caller |
| `githubsts_github_secondary_rate_limit_total` | Counter | Secondary (abuse) rate limit events, by app, instance, caller |
| `githubsts_github_secondary_rate_limit_retry_after_seconds` | Gauge | Current retry-after in seconds, by app, instance |

Every pool member (`instance` label) has its own rate limit series: an app with 3 instances reports 3 independent `githubsts_github_rate_limit_remaining` series, not one aggregate. A single-instance (non-pooled) app still carries the label, with `instance` equal to that app's one normalized instance.

## GitHub reachability

| Metric | Type | Description |
|---|---|---|
| `githubsts_github_reachable` | Gauge | GitHub API reachability (1/0) by app, instance |
| `githubsts_github_reachability_check_duration_seconds` | Histogram | Latency of reachability probes, by app, instance |
| `githubsts_github_reachability_failures_total` | Counter | Reachability probe failures, by app, instance, reason |

## App pool metrics

Visibility into instance selection for a pooled app (`apps.<name>.instances`; see [Configuration]({{< relref "/reference/configuration#app-pools-multi-instance-rate-limit-rotation" >}})). A non-pooled app is a pool of one and still emits these, with `instances=1` and every selection outcome `selected`. The `instance` label throughout this page identifies one physical GitHub App within a pool, not a github-sts server replica.

| Metric | Type | Description |
|---|---|---|
| `githubsts_app_pool_instances` | Gauge | Configured pool size, by app |
| `githubsts_app_pool_selection_total` | Counter | Selection outcomes, by app, instance, outcome |
| `githubsts_app_pool_exhausted_total` | Counter | Requests where every pool instance failed, by app |

`githubsts_app_pool_selection_total`'s `outcome` label is one of `selected`, `skipped_unreachable`, or `failover` today. (`skipped_rate_limited` is reserved for the planned `rate_limit_aware` strategy, which is not yet implemented; see [Configuration]({{< relref "/reference/configuration#app-pools-multi-instance-rate-limit-rotation" >}}).)

`githubsts_app_pool_exhausted_total` is the signal worth alerting on: it means every instance in that app's pool failed for one request. A single instance's rate-limit gauge dropping doesn't by itself mean requests are failing: the pool has already failed over around it.

## Enterprise Rego bundle metrics

| Metric | Type | Description |
|---|---|---|
| `githubsts_bundle_enforcement_required` | Gauge | `1` in required mode; `0` in explicitly optional mode |
| `githubsts_org_decision_total` | Counter | Enterprise Rego outcomes by app, bundle, and result (`allow`, `deny`, `error`, or `not_evaluated`) |
| `githubsts_bundle_pull_total` | Counter | Bundle pull attempts by bundle and result |
| `githubsts_bundle_verify_total` | Counter | Cosign verification attempts by bundle and result (`success`, `failure`, or explicit `skipped`) |
| `githubsts_bundle_loaded_digest_info` | Gauge | Current loaded bundle digest by bundle |
| `githubsts_bundle_age_seconds` | Gauge | Seconds since last successful bundle pull by bundle |
| `githubsts_bundle_reload_total` | Counter | Bundle reload attempts by bundle and result |
| `githubsts_bundle_stale_evals_total` | Counter | Exchanges evaluated with stale bundles by bundle and fail mode |
| `githubsts_bundle_policy_revision_info` | Gauge | Active signed Rego tuple by bundle, digest, and policy revision |
| `githubsts_bundle_policy_revision_changes_total` | Counter | Policy revision reload outcomes by bundle |
| `githubsts_bundle_policy_decisions_total` | Counter | Aggregate Rego decision impact by app, bundle, digest, and result |
| `githubsts_bundle_policy_rule_decisions_total` | Counter | Rego decisions by bounded enterprise rule ID |
| `githubsts_bundle_policy_exceptions_total` | Gauge | Discovered exception inventory by bundle, digest, and status |
| `githubsts_bundle_policy_exception_expiration_timestamp_seconds` | Gauge | Exception expiration timestamp by bundle, digest, exception ID, rule ID, and owner |
| `githubsts_bundle_policy_exception_seconds_until_expiration` | Gauge | Seconds until exception expiration by bundle, digest, exception ID, rule ID, and owner |
| `githubsts_bundle_policy_exception_hits_total` | Counter | Exchanges where a Rego decision reported an exception hit |

Check `/health.security.bundle_enforcement`, `enterprise_policy_required`, and
`yaml_only_authorization` after every rollout. Each configured `bundles[]`
status reports `mandatory` and the admitted `policy_revision` alongside
digest, age, enabled state, and pull errors. Health remains liveness-only
even when an exchange would fail closed.

Exchange audit events include `bundle_enforcement`. Once the bundle path is
reached, they add `bundle_digest` and `org_decision.applicable` /
`org_decision.evaluated`; completed evaluations add `bundle_decisions`, whose
entries include the exact evaluated `digest` and `policy_revision`. Preserve
these fields in the SIEM so an evaluated `403 org_policy_denied` remains
distinguishable from the bundle-related `503` errors.

## Audit metrics

| Metric | Type | Description |
|---|---|---|
| `githubsts_audit_events_logged_total` | Counter | Audit events logged by result |
| `githubsts_audit_log_errors_total` | Counter | Audit log write errors by backend |
| `githubsts_audit_events_dropped_total` | Counter | Audit events dropped (full buffer) |

## Other metrics

| Metric | Type | Description |
|---|---|---|
| `githubsts_rate_limit_rejections_total` | Counter | Requests rejected by per-IP rate limiting |
| `githubsts_ready` | Gauge | Instance readiness (1/0) |

## Recommended alerts

```promql
# Sustained OIDC validation errors: possible misconfiguration or attack
rate(githubsts_oidc_validation_errors_total[5m]) > 0

# JTI replay attempts: investigate immediately
rate(githubsts_jti_replay_attempts_total[5m]) > 0

# GitHub API unreachable: tokens will fail
githubsts_github_reachable == 0

# Audit events dropped: increase buffer or sink throughput
rate(githubsts_audit_events_dropped_total[5m]) > 0

# Exchange latency regression
histogram_quantile(0.99, rate(githubsts_token_exchange_duration_seconds_bucket[5m])) > 1

# Rate limit approaching exhaustion
githubsts_github_rate_limit_remaining_percent < 10

# Secondary rate limit active
githubsts_github_secondary_rate_limit_total > 0

# App pool exhausted: every instance failed a request
rate(githubsts_app_pool_exhausted_total[5m]) > 0

# Deployment is running in explicitly optional enterprise-policy posture
githubsts_bundle_enforcement_required == 0

# Bundle pull is failing
rate(githubsts_bundle_pull_total{result="failure"}[5m]) > 0

# Bundle signature verification is failing
rate(githubsts_bundle_verify_total{result="failure"}[5m]) > 0

# Bundle is stale; fail-closed bundles return 503 bundle_stale
githubsts_bundle_age_seconds > max_staleness_seconds

# Active Rego revision changed: review decision impact metrics
increase(githubsts_bundle_policy_revision_changes_total{result="changed"}[10m]) > 0

# Exception expires in less than seven days
githubsts_bundle_policy_exception_seconds_until_expiration < 604800

# Expired exceptions remain in the loaded bundle
githubsts_bundle_policy_exceptions_total{status="expired"} > 0
```
