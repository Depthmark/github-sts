---
title: Tracing token exchanges
description: Configure OpenTelemetry and read the request, policy, bundle, and GitHub spans emitted by github-sts.
weight: 5
translationKey: tracing-token-exchanges
---

Enable tracing when you need to locate latency or dependency failures inside a token exchange. The service exports OTLP traces and returns the active trace ID in `X-Trace-ID` and error responses.

## Configure tracing

Send traces to an OpenTelemetry Collector reachable from the service:

```yaml
tracing:
  enabled: true
  endpoint: "otel-collector.observability.svc:4317"
  protocol: grpc
  insecure: true
  sample_ratio: 1.0
  timeout: 10s
  service_name: github-sts
  environment: dev
```

`protocol` accepts `grpc` or `http`. Keep `sample_ratio` at `1.0` when a Collector performs tail sampling. A head sampler cannot know the final exchange result and may otherwise discard denials, slow requests, and failed pool attempts.

Use the corresponding `GITHUBSTS_TRACING_*` environment variables for the scalar fields when configuration comes from the environment. The `headers` map has no `GITHUBSTS_TRACING_HEADERS` override. If the exporter requires authentication, inject a configuration file containing `tracing.headers` from a secret store rather than committing the values.

## Read an exchange trace

The root span is named `GET /sts/exchange` or `POST /sts/exchange`. For a request that reaches OIDC handling, its `sts.result` attribute uses the same closed result set as the audit event. Requests rejected earlier for their HTTP method, shape, fields, or scope contain the HTTP status without `sts.result`. Request stages appear as sibling spans so their durations form a readable waterfall:

| Span | Operation |
|---|---|
| `sts.oidc.validate` | Validate the bearer token and its signature |
| `sts.jti.reserve` | Reserve the replay-prevention key |
| `github.target.resolve` | Resolve the target repository to its canonical immutable identity |
| `sts.policy.load` | Load the applicable trust policy, including any policy-read token and GitHub file request |
| `sts.policy.validate` | Validate the trust-policy structure |
| `sts.policy.evaluate` | Evaluate issuer, subject, and claim selectors |
| `sts.policy.relationship` | Evaluate the immutable source-to-target relationship |
| `sts.permissions.narrow` | Apply caller-requested permission narrowing |
| `sts.bundle.evaluate` | Evaluate enabled organization policy bundles |
| `sts.token.issue` | Coordinate issuance of the caller-facing token |

GitHub operations add more detail below these stages:

```text
sts.policy.load
└── github.app_pool.attempt
    └── github.token.mint          sts.token.purpose=policy_fetch
        ├── github.installation.resolve  sts.cache.result=hit|miss|shared
        ├── github.app_jwt.get           sts.cache.result=hit|miss
        │   └── github.app_jwt.sign
        └── HTTP POST              http.response.status_code=201|422|...
```

`github.app_jwt.sign` appears only when the service performs RSA signing. A cache hit produces `github.app_jwt.get` without a signing child. Outbound GitHub, OIDC discovery, and JWKS requests use OpenTelemetry HTTP client spans.

## Diagnose a policy-read 502

A GitHub HTTP 422 while loading a policy produces this failure path:

```text
GET /sts/exchange                 sts.result=github_error, status=ERROR
└── sts.policy.load              error.type=policy_load_failed
    └── github.app_pool.attempt  github.app.instance=<attempted instance>
        └── github.token.mint    sts.token.purpose=policy_fetch
            └── HTTP POST        http.response.status_code=422
```

The mint span reports `error.type=github_permissions_not_granted`. Check that the selected GitHub App installation has the requested permission and access to the policy repository.

Authorization denials such as `policy_denied` and `org_policy_denied` remain status `Unset`. Their `sts.result` and `sts.stage.result=denied` attributes distinguish them from service or dependency failures without inflating error-rate alerts.

## Data safety

Spans never include bearer tokens, GitHub installation tokens, App JWT values, private keys, authorization headers, request bodies, raw claims maps, registry credentials, or upstream response bodies. Error spans use bounded `error.type` values instead of raw error messages. Audit logs remain the detailed record for authorization decisions.

## Verify the trace

1. Send one exchange request that reaches OIDC validation with tracing enabled.
2. Copy `X-Trace-ID` from the response.
3. Open that trace in Tempo.
4. Confirm the root span contains `sts.result` and the waterfall contains the stages reached by the request.

Stages after a rejection are absent because the handler does not execute them. Child spans are also absent when the root trace is not sampled.
