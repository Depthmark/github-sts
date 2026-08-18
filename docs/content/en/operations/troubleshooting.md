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
| **Startup fails** with `bundle_enforcement is required` | Set top-level `bundle_enforcement` or `GITHUBSTS_BUNDLE_ENFORCEMENT` to exactly `required` or `optional`. There is no implicit default. |
| **Required-mode startup fails bundle validation** | Configure exactly one global bundle with `apps: []` and `fail_mode: closed`. Every required-mode bundle must be cosign verified and use an OCI ref pinned to `@sha256:` plus 64 lowercase hex characters. |
| **Startup fails mandatory bundle admission** | Verify the baseline exposes `data.sts.enterprise.v1.decision` and `.metadata`; metadata declares v1, a nonempty policy revision, both required controls, and a known-good admission context. That context must allow and all four isolated negative probes must deny. |
| **Startup warns that enterprise bundle enforcement is optional** | This is deliberate posture signaling. Use `required` for production. `/health.security.yaml_only_authorization` is `true` if no bundles are configured or any App lacks bundle coverage. |

### OIDC validation

| Problem | Solution |
|---|---|
| **Exchange returns `401`** | Missing or malformed `Authorization: Bearer` header. Check the workflow actually requested an OIDC token (`id-token: write` permission). |
| **Exchange returns `403`** with `code: "oidc_invalid"` | OIDC token rejected. Check token expiry, verify `oidc.allowed_issuers` includes the issuer, confirm `kid` is present, review server logs at `trace_id`. |
| **Exchange returns `403`** with `code: "github_identity_invalid"` | GitHub.com source identity is missing string owner/repository ID claims, the claims disagree, or `sub` is still name-only while immutable format is required. Opt the repository in to immutable subjects and inspect the audit reason at `trace_id`. |
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
| **Exchange returns `403`** with `code: "trust_policy_invalid"` | The policy lacks a selector or exact GitHub source/target IDs, or another policy field is malformed. Validate and fix the target policy. |
| **Exchange returns `403`** with `code: "policy_denied"` | A valid policy did not match the workload selector or immutable source-to-target relationship. Grep server logs for `trace_id` for the precise mismatch. |
| **Exchange returns `403`** with `code: "org_policy_denied"` | Enterprise policy was evaluated and denied. Inspect audit `bundle_digest`, `bundle_decisions`, and the org decision fields at `trace_id`. |
| **Exchange returns `404`** | Same root cause as `policy_not_found`: file path is wrong, or the GitHub App lacks read access to the policy file. |
| **Exchange returns `503`** with `code: "bundle_stale"` | A fail-closed bundle exceeded `max_staleness`. Restore pull/verification and retry after a successful refresh. |
| **Exchange returns `503`** with `code: "bundle_unavailable"` | Required enforcement could not prove mandatory baseline participation. Check `/health` per-bundle `mandatory`, `enabled`, digest, policy revision, and pull error fields. |
| **Exchange returns `503`** with `code: "bundle_evaluation_failed"` | Evaluation faulted rather than returning a deny. Correlate `trace_id` for timeout, strict built-in, or malformed-result details. |

### Replay

| Problem | Solution |
|---|---|
| **Exchange returns `409`** with `code: "replay_detected"` | The OIDC token's `jti` was already used. Obtain a fresh token. If you are running multiple replicas, set `GITHUBSTS_JTI_BACKEND=redis`. |

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

2. **Set `GITHUBSTS_SERVER_LOG_LEVEL=debug`** temporarily. Each exchange logs the validation pipeline at this level, with the `trace_id` correlating server-side reasons to the response code.
3. **Decode the OIDC token** locally to confirm `iss`, `sub`, `aud`, `repository_owner_id`, `repository_id`, and any custom claims:
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
   - `github.sources[]` contains the token's exact owner/repository ID pair
   - `github.target` matches the target owner/repository IDs shown in audit

## Verify bundle posture

```bash
curl -s http://localhost:8080/health | jq '{security, bundles}'
curl -s http://localhost:8080/metrics | grep githubsts_bundle_enforcement_required
```

Production should report `bundle_enforcement: "required"`,
`enterprise_policy_required: true`, `yaml_only_authorization: false`, and metric
value `1`. Per-bundle health should identify exactly one `mandatory: true`
baseline whose `policy_revision` matches its configured
`expected_policy_revision`. Audit events always carry
`bundle_enforcement`; when evaluation runs, use `org_decision.applicable` and
`org_decision.evaluated` to distinguish participation from a fault. Evaluated
`bundle_decisions[]` entries include the signed revision and digest.

If startup or reload reports a revision mismatch, compare the deployed
`expected_policy_revision` with `.manifest.revision` from the cosign-verified
artifact and with mandatory Rego `metadata.policy_revision`. Do not bypass the
check or retag the image; promote a matching digest/revision tuple.

## Where to look next

- [API Reference]({{< relref "/reference/api#error-responses" >}}): full error code table.
- [Configuration]({{< relref "/reference/configuration" >}}): every YAML/env knob.
- [OIDC Issuers]({{< relref "/oidc-issuers" >}}): per-provider issuer/JWKS setup.
- [Architecture]({{< relref "/concepts/architecture#authorization-pipeline" >}}): exact order of checks.
- Open an issue: <https://github.com/Depthmark/github-sts/issues>
