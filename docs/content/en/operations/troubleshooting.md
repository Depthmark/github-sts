---
title: Troubleshooting
description: Error-code-first diagnostics, trace_id correlation, OIDC checks, policy checks, and recovery steps.
weight: 4
translationKey: troubleshooting
---

When an exchange fails, the JSON error response carries two useful fields. `code` is the machine-readable error code that tells you which layer rejected the request. `trace_id` correlates the response to a server log line that carries the full reason. `error` is deliberately generic; branch on `code`, not on `error`.

```json
{ "error": "forbidden", "code": "policy_denied", "trace_id": "abc-123" }
```

```bash
# In your server logs / kubectl logs
grep abc-123 /var/log/github-sts.log
```

## Common errors

### Deployment

| Problem | Solution |
|---|---|
| **Docker build fails** with `go.mod requires go >= X` | Update `FROM golang:X-alpine` in `Dockerfile` to match `go.mod` |
| **Health check fails** | Verify `GITHUBSTS_CONFIG_PATH` is set and the file exists |

### OIDC validation

| Problem | Solution |
|---|---|
| **Exchange returns `401`** | Missing or malformed `Authorization: Bearer` header. Check the workflow actually requested an OIDC token (`id-token: write` permission). |
| **Exchange returns `403`** with `code: "oidc_invalid"` | OIDC token rejected. Check token expiry, verify `oidc.allowed_issuers` includes the issuer, confirm `kid` is present, review server logs at `trace_id`. |
| **JWKS host rejected** in logs | Issuer's `jwks_uri` host differs from the issuer host. Add it to `oidc.trusted_jwks_hosts` (see [OIDC Issuers]({{< relref "/oidc-issuers" >}})). |

### Audience

| Problem | Solution |
|---|---|
| **Exchange returns `403`** with `code: "audience_mismatch"` | Token's `aud` does not match. Verify `core.getIDToken(<audience>)` in the workflow uses the same value as the policy's `audience:` field (and `oidc.required_audience` if configured server-side). |

### Policy

| Problem | Solution |
|---|---|
| **Exchange returns `403`** with `code: "app_unknown"` | `?app=` does not match a configured app. Check spelling or omit when only one app is configured. |
| **Exchange returns `403`** with `code: "policy_not_found"` | Verify the trust policy exists at `{base_path}/{app}/{identity}.sts.yaml` in the target repo (or org policy repo, depending on `policy_resolution`). A wrong file path or a GitHub App that lacks read access to the policy file produces the same error. |
| **Exchange returns `403`** with `code: "policy_denied"` | Policy exists but evaluation failed (subject, claim_pattern). Grep server logs for `trace_id` for the precise mismatch. |

### Replay

| Problem | Solution |
|---|---|
| **Exchange returns `409`** with `code: "replay_detected"` | The OIDC token's `jti` was already used. Obtain a fresh token. If you are running multiple replicas, set `GITHUBSTS_JTI_BACKEND=redis`. |

### App pools

| Problem | Solution |
|---|---|
| **Exchange returns `502`** with `code: "upstream_error"` and `githubsts_app_pool_exhausted_total` rising for that app | Every instance in the app's pool failed for this request, not just one. Check each instance's credentials and installation individually: `githubsts_github_reachable{app=...,instance=...}` and the `instance`-labeled log lines around the failure narrow it to a specific one. |
| **One instance never gets selected (`githubsts_app_pool_selection_total{...,outcome="skipped_unreachable"}` climbing for it)** | The reachability prober currently reports that instance down. Confirm its credentials and GitHub App installation are still valid; a revoked or misconfigured key looks the same as a network partition from the pool's point of view. |
| **`rotation.strategy: rate_limit_aware` doesn't change instance selection** | Expected in this release: `rate_limit_aware` is accepted as config but not yet implemented; the pool behaves like `round_robin`. Check the startup log for the `rotation.strategy=rate_limit_aware is configured but this build does not yet implement...` warning. See [Configuration]({{< relref "/reference/configuration#app-pools-multi-instance-rate-limit-rotation" >}}). |
| **Startup log: `app_id N is used by more than one logical app`** | A warning, not an error: two logical apps' pools share the same `app_id`, so they share one GitHub rate-limit bucket. Allowed, but confirm it's intentional rather than a copy-pasted instance block. |

### Upstream and audit

| Problem | Solution |
|---|---|
| **Exchange returns `502`** with `code: "upstream_error"` | Policy fetch or GitHub token mint failed. Check `githubsts_github_reachable` metric and server logs at `trace_id`. |
| **Audit events dropped** (`githubsts_audit_events_dropped_total` rising) | Audit sink can't keep up. Increase `GITHUBSTS_AUDIT_BUFFER_SIZE`, ensure the audit log path is writable, or speed up the audit consumer. |

## Debugging an exchange end-to-end

1. **Obtain an OIDC token** from your identity provider. In GitHub Actions, request one with `id-token: write` and `core.getIDToken()`:

   ```bash
   # In a workflow step that has id-token: write
   #   const token = await core.getIDToken('https://sts.example.com')
   # Or, outside a workflow, use your provider's CLI (e.g. gcloud auth print-identity-token).
   export OIDC_TOKEN="<the token>"
   ```

2. **Set `GITHUBSTS_SERVER_LOG_LEVEL=debug`** temporarily. Each exchange logs the validation pipeline at this level.
3. **Decode the OIDC token** locally to confirm `iss`, `sub`, `aud`, and any custom claims:
   ```bash
   echo "$OIDC_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
   ```
4. **Read the trust policy** the server is loading:
   ```bash
   gh api repos/myorg/myrepo/contents/.github/sts/default/ci.sts.yaml \
     --jq .content | base64 -d
   ```
5. **Compare claims to the policy line by line:**
   - `policy.issuer == token.iss` (exact match)
   - `policy.subject == token.sub` (or `subject_pattern` regex matches `token.sub`)
   - `policy.audience == token.aud` (and `oidc.required_audience` if set)
   - Each `claim_pattern[k]` regex matches `token[k]`

## Where to look next

- [API Reference]({{< relref "/reference/api#error-responses" >}}): full error code table.
- [Configuration]({{< relref "/reference/configuration" >}}): every YAML/env knob.
- [OIDC Issuers]({{< relref "/oidc-issuers" >}}): per-provider issuer/JWKS setup.
- [Architecture]({{< relref "/concepts/architecture#authorization-pipeline" >}}): exact order of checks.
- Open an issue: <https://github.com/Depthmark/github-sts/issues>
