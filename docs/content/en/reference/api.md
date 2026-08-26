---
title: API Reference
description: HTTP endpoints, methods, parameters, responses, error codes, health checks, and Go client examples.
weight: 1
translationKey: api
---

## Token Exchange

### `GET /sts/exchange`

Exchange an OIDC bearer token for a scoped GitHub installation token.

| Parameter | Required | Description |
|---|---|---|
| `scope` | Yes | Exact current canonical `org/repo` target. Organization-level scopes are rejected. |
| `identity` | Yes | Policy selector, maps to `{base_path}/{app}/{identity}.sts.yaml` |
| `app` | No | App name (defaults to single configured app) |

```bash
curl -H "Authorization: Bearer $OIDC_TOKEN" \
  "http://localhost:8080/sts/exchange?scope=myorg/myrepo&app=default&identity=ci"
```

### `POST /sts/exchange`

Same endpoint, JSON body variant.

```bash
curl -X POST -H "Authorization: Bearer $OIDC_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"scope":"myorg/myrepo","app":"default","identity":"ci"}' \
  http://localhost:8080/sts/exchange
```

### Response

**Success (200):**

```json
{
  "token": "ghs_xxxxxxxxxxxxxxxxxxxx",
  "scope": "myorg/myrepo",
  "app": "default",
  "identity": "ci",
  "permissions": {
    "contents": "read",
    "pull_requests": "write"
  }
}
```

The returned `ghs_…` token is a standard GitHub App installation token. It expires according to GitHub's installation token lifetime (currently one hour).

### Error responses

Error responses share this shape:

```json
{ "error": "forbidden", "code": "policy_denied", "trace_id": "abc-123" }
```

`error` is deliberately generic so attackers can't probe the validator. Use the `code` field (the machine-readable error code) to branch in your client logic, and `trace_id` to correlate with server/audit logs (the log line carries the full reason).

| Status | `code` | What to fix |
|---|---|---|
| `400` | `bad_request` | Missing/invalid query params, malformed/non-canonical target scope, unsupported organization scope, or invalid JSON body. |
| `403` | `oidc_invalid` | OIDC token rejected (missing/expired, bad signature, unknown `iss`, missing `kid`, malformed). Refresh or re-mint the token; verify `allowed_issuers`. |
| `403` | `github_identity_invalid` | GitHub.com source identity is missing immutable ID claims, has contradictory repository claims, or uses a legacy `sub` while immutable subjects are required. Check repository OIDC settings and the audit reason at `trace_id`. |
| `403` | `audience_mismatch` | Token's `aud` does not match the policy's `audience:`. Pass the right value to `core.getIDToken(<audience>)` or update the policy. |
| `403` | `app_unknown` | `?app=` does not match a configured app. Check spelling or omit when only one app is configured. |
| `403` | `policy_not_found` | No `.sts.yaml` for this `scope/app/identity`. Verify the file path: `{base_path}/{app}/{identity}.sts.yaml` in the target (or org policy) repo. |
| `403` | `trust_policy_invalid` | The loaded policy is malformed, lacks a workload selector or required GitHub ID binding, or otherwise violates the policy contract. Fix the target policy; details are in the audit log. |
| `403` | `policy_denied` | A valid policy did not match the workload or exact immutable source-to-target relationship. Check the audit log line at `trace_id` for the precise mismatch. |
| `403` | `org_policy_denied` | Enterprise policy was evaluated and denied the exchange after the YAML policy allowed it. Check audit `bundle_decisions` for bundle, package, rule, exception, and reason details. |
| `405` | `method_not_allowed` | Use `GET` or `POST`. |
| `409` | `replay_detected` | JTI already consumed; obtain a fresh OIDC token. |
| `503` | `bundle_stale` | A configured bundle is older than `max_staleness` and uses fail-closed behavior. Restore bundle pull/verification or raise `max_staleness` intentionally. |
| `503` | `bundle_unavailable` | Required mode could not prove that the mandatory baseline participated. Restore the global baseline and retry. |
| `503` | `bundle_evaluation_failed` | Bundle evaluation faulted, such as a timeout, strict built-in error, or malformed decision result. Inspect the server log at `trace_id`. |
| `500` | `internal_error` | Server-side problem (cache backend, app misconfig). Check server logs at `trace_id`. |
| `502` | `upstream_error` | Policy fetch or GitHub token mint failed. Check server logs at `trace_id`. |

Bundle-related audit events always include `bundle_enforcement`. Once the bundle
path is reached, `bundle_digest` and `org_decision.applicable` /
`org_decision.evaluated` record participation; completed evaluations add
`bundle_decisions`. This distinguishes `org_policy_denied` from dependency and
evaluation failures.

## Trust Policy Validation

### `POST /sts/v1/trust-policy/validate`

Validate and lint `.github/sts/{app}/{identity}.sts.yaml` content for editor tooling such as VS Code. This endpoint validates the YAML trust-policy contract only. It does not evaluate enterprise Rego bundles and never returns exception inventory.

Send raw YAML:

```bash
curl -X POST http://localhost:8080/sts/v1/trust-policy/validate \
  -H "Content-Type: application/x-yaml" \
  --data-binary @.github/sts/default/ci.sts.yaml
```

Or send JSON:

```bash
curl -X POST http://localhost:8080/sts/v1/trust-policy/validate \
  -H "Content-Type: application/json" \
  -d '{"content":"issuer: https://issuer.example.com\nsubject: workload-1\naudience: https://sts.example.com\npermissions:\n  contents: read\n"}'
```

Successful validation returns `200` with `valid: true` and canonical formatted YAML:

```json
{
  "valid": true,
  "diagnostics": [],
  "formatted": "issuer: https://issuer.example.com\nsubject: workload-1\naudience: https://sts.example.com\npermissions:\n    contents: read\n"
}
```

Invalid policy content returns `422` with diagnostics:

```json
{
  "valid": false,
  "diagnostics": [
    {
      "severity": "error",
      "code": "subject_conflict",
      "message": "subject and subject_pattern are mutually exclusive",
      "path": "$.subject_pattern",
      "line": 3,
      "column": 1
    }
  ]
}
```

Diagnostic severities are `error` or `warning`. Errors include YAML parse errors, unknown fields, selector conflicts, unsupported `repositories`, invalid immutable IDs, and the same trust-policy validation errors enforced by the exchange path.

### `GET /sts/v1/trust-policy.json`

Return the JSON Schema file from the loaded bundle at `/data/sts/v1/trust-policy.json`. This is intended for editor schema association. The schema endpoint depends on an enabled bundle that ships the schema document and returns `503` if the bundle integration is disabled or the schema file is missing.

## Token Revocation

Tokens issued by github-sts are standard GitHub App installation tokens and can be revoked directly via the GitHub API:

```bash
curl -X DELETE https://api.github.com/installation/token \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json"
# 204 = revoked, 401/404 = already expired
```

Or via the Go client:

```go
err := client.RevokeToken(ctx, token, "https://api.github.com")
```

When you use the `github-sts-action`, the token is revoked automatically at the end of the job. See [Use the GitHub Action]({{< relref "/integrations/use-github-action" >}}) for details.

## Health & Readiness

| Endpoint | Method | Success | Failure |
|---|---|---|---|
| `/health` | `GET` | `200` with liveness, security posture, and configured bundle state | `401` when health authentication is configured and the Bearer token is missing or incorrect |
| `/ready` | `GET` | `200` `{"ready":true}` | `503` `{"ready":false}` |
| `/metrics` | `GET` | Prometheus text format | n/a |

`/health` is a liveness probe. When authentication is disabled or satisfied,
it returns `200` as long as the process is up.
Set `health.auth_token` or `GITHUBSTS_HEALTH_AUTH_TOKEN` to require an
`Authorization: Bearer <token>` header. A missing or incorrect token returns
`401` with `{"error":"unauthorized"}` and
`WWW-Authenticate: Bearer realm="health"`. When neither setting supplies a
token, `/health` remains unauthenticated. `/ready` stays unauthenticated.

After starting github-sts with `GITHUBSTS_HEALTH_AUTH_TOKEN` set, verify the
behavior from the same host:

```bash
export GITHUBSTS_HEALTH_AUTH_TOKEN="replace-with-the-configured-secret"

curl -o /dev/null -s -w '%{http_code}\n' http://127.0.0.1:8080/health
# 401

curl -o /dev/null -s -w '%{http_code}\n' \
  -H "Authorization: Bearer $GITHUBSTS_HEALTH_AUTH_TOKEN" \
  http://127.0.0.1:8080/health
# 200
```

Use HTTPS whenever the Bearer token crosses a network. The loopback example
uses HTTP only for local verification.

Its `security` object reports `require_immutable_subject_claims`,
`legacy_subject_opt_out`, `bundle_enforcement`,
`enterprise_policy_required`, and `yaml_only_authorization`. Explicit optional
mode reports `enterprise_policy_required: false`; `yaml_only_authorization` is
true when no bundle is configured or at least one App lacks bundle coverage.
`/ready` returns `200` with `{"ready":true}` once the server is serving and
`503` with `{"ready":false}` while it is not. Readiness is not gated on GitHub
API reachability; the reachability prober only updates the
`githubsts_github_reachable` metric. Use `/ready` for Kubernetes readiness
probes and load balancer health checks.

When bundles are configured, `/health` includes aggregate bundle state and a
`bundles` array. Per-bundle status includes `name`, `enabled`, `mandatory`,
`digest`, authoritative signed manifest `policy_revision`, `age_seconds`, and optional
`last_pull_error`. Bundle pull failures do not change liveness; exchange-time
behavior follows each bundle's `fail_mode` and required-participation contract.

Completed exchange audit events include `policy_revision` in each
`bundle_decisions[]` entry alongside the exact evaluated digest.

## Go Client Library

```go
import "github.com/depthmark/github-sts/client"

// Direct GitHub App token (requires the App private key)
provider, err := client.NewAppTokenProvider(appID, pemData, "myorg", "https://api.github.com")
if err != nil { /* handle */ }
token, err := provider.Token(ctx)

// STS token exchange (requires an OIDC token and the STS URL)
stsProvider := &client.STSTokenProvider{
    STSURL:     "https://sts.example.com",
    Identity:   "ci",
    Scope:      "myorg/myrepo",
    App:        "default",
    Audience:   "https://sts.example.com",
    SATokenPath: client.DefaultSATokenPath,
}
token, err = stsProvider.Token(ctx)

// Token revocation
err = client.RevokeToken(ctx, token, "https://api.github.com")
```

`NewAppTokenProvider(appID int64, pemData []byte, owner, apiURL string, opts ...Option)` returns `(*AppTokenProvider, error)`; its `Token(ctx context.Context) (string, error)` method mints a token. `STSTokenProvider` is a plain struct with a `Token(ctx)` method (there is no constructor). `client.DefaultSATokenPath` is `/var/run/secrets/tokens/github-sts-token`.

The client lives at [`client/`](https://github.com/Depthmark/github-sts/tree/main/client) and is importable as `github.com/depthmark/github-sts/client`.
