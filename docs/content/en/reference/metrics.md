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
| `githubsts_token_exchanges_total` | Counter | Exchange attempts by app, scope, identity, issuer, result |
| `githubsts_token_exchange_duration_seconds` | Histogram | Exchange latency by app, scope, identity, issuer |
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
| `githubsts_github_api_calls_total` | Counter | GitHub API calls by app, endpoint, result |
| `githubsts_github_tokens_issued_total` | Counter | Tokens issued by app, scope, permissions |
| `githubsts_github_rate_limit_remaining` | Gauge | Remaining rate limit by app, resource |
| `githubsts_github_rate_limit_limit` | Gauge | Maximum requests allowed in current window |
| `githubsts_github_rate_limit_used` | Gauge | Requests used in current window |
| `githubsts_github_rate_limit_reset_timestamp` | Gauge | Unix epoch timestamp when window resets |
| `githubsts_github_rate_limit_remaining_percent` | Gauge | Percentage of rate limit remaining |
| `githubsts_github_rate_limit_exceeded_total` | Counter | Primary rate limit exceeded events |
| `githubsts_github_secondary_rate_limit_total` | Counter | Secondary (abuse) rate limit events |
| `githubsts_github_secondary_rate_limit_retry_after_seconds` | Gauge | Current retry-after in seconds |

## GitHub reachability

| Metric | Type | Description |
|---|---|---|
| `githubsts_github_reachable` | Gauge | GitHub API reachability (1/0) by app |
| `githubsts_github_reachability_check_duration_seconds` | Histogram | Latency of reachability probes |
| `githubsts_github_reachability_failures_total` | Counter | Reachability probe failures |

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
```
