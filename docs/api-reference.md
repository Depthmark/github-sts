# API Reference

## Token Exchange

### `GET /sts/exchange`

Exchange an OIDC bearer token for a scoped GitHub installation token.

| Parameter | Required | Description |
|---|---|---|
| `scope` | Yes | `org/repo` (repo-level) or `org` (org-level) |
| `identity` | Yes | Policy selector — maps to `{base_path}/{app}/{identity}.sts.yaml` |
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

`error` is deliberately generic so attackers can't probe the validator. Use `code` to branch in your client and `trace_id` to correlate with server/audit logs (the log line carries the full reason).

| Status | `code` | What to fix |
|---|---|---|
| `400` | `bad_request` | Missing/invalid query params or JSON body. |
| `403` | `oidc_invalid` | OIDC token rejected (missing/expired, bad signature, unknown `iss`, missing `kid`, malformed). Refresh or re-mint the token; verify `allowed_issuers`. |
| `403` | `audience_mismatch` | Token's `aud` does not match the policy's `audience:`. Pass the right value to `core.getIDToken(<audience>)` or update the policy. |
| `403` | `app_unknown` | `?app=` does not match a configured app. Check spelling or omit when only one app is configured. |
| `403` | `policy_not_found` | No `.sts.yaml` for this `scope/app/identity`. Verify the file path: `{base_path}/{app}/{identity}.sts.yaml` in the target (or org policy) repo. |
| `403` | `policy_denied` | Policy exists but evaluation failed (subject, claim_pattern). Check the audit log line at `trace_id` for the precise mismatch. |
| `405` | `method_not_allowed` | Use `GET` or `POST`. |
| `409` | `replay_detected` | JTI already consumed; obtain a fresh OIDC token. |
| `500` | `internal_error` | Server-side problem (cache backend, app misconfig). Check server logs at `trace_id`. |
| `502` | `upstream_error` | Policy fetch or GitHub token mint failed. Check server logs at `trace_id`. |

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

## Health & Readiness

| Endpoint | Method | Success | Failure |
|---|---|---|---|
| `/health` | `GET` | `200` `{"status":"ok"}` | — |
| `/ready` | `GET` | `200` `{"status":"ready"}` | `503` `{"status":"not ready"}` |
| `/metrics` | `GET` | Prometheus text format | — |

`/health` is a liveness probe — it returns `200` as long as the process is up. `/ready` returns `503` until startup checks (config load, GitHub API reachability) succeed; use it for Kubernetes readiness probes and load balancer health checks.

## Go Client Library

```go
import "github.com/depthmark/github-sts/client"

// Direct GitHub App token (requires private key)
provider, _ := client.NewAppTokenProvider(appID, orgOrOwner, pemBytes)
token, _ := provider.Token(ctx, "org/repo", "ci", permissions, nil)

// STS token exchange (requires OIDC token + STS URL)
stsProvider := client.NewSTSTokenProvider(stsURL, oidcTokenPath)
token, _ := stsProvider.Token(ctx, "org/repo", "ci", "my-app", "")

// Token revocation
err := client.RevokeToken(ctx, token, "https://api.github.com")
```

The client lives at [`client/`](https://github.com/Depthmark/github-sts/tree/main/client) and is importable as `github.com/depthmark/github-sts/client`.
