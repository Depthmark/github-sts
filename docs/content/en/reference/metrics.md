---
title: Metrics
description: Prometheus metric names, types, labels, operational meaning, and recommended alert queries.
weight: 4
translationKey: metrics
---

All metrics are exposed at `GET /metrics` in Prometheus text format with the `githubsts_` prefix.

## HTTP metrics

| Metric | Type | Description |
|---|---|---|
| `githubsts_http_requests_total` | Counter | HTTP requests by method, path, status |
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
```
