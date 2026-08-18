---
title: OIDC Issuers
description: "Configure GitHub Actions, Azure, and generic OIDC issuers: JWKS discovery, audience setup, and validation steps."
weight: 4
translationKey: oidc-issuers
---

This section covers how to configure `github-sts` to validate OIDC tokens from
identity providers. The verifier requires every token to:

1. Have an `iss` claim that is in `oidc.allowed_issuers`.
2. Carry a `kid` in the JWT header that matches a key in the issuer's JWKS.
3. Resolve a `jwks_uri` (via OIDC discovery) whose host either matches the
   issuer host or is opted in via `oidc.trusted_jwks_hosts`.
4. Carry an `aud` claim that matches the policy's `audience:` field (mandatory
   in every policy) and, if set, the server-wide `oidc.required_audience`.

> **Audience pitfall.** Most OIDC libraries default `aud` to something useful
> only to the issuer (e.g., GitHub Actions defaults to the workflow repo URL).
> That default is **not safe** for an STS: every workflow in the org would be
> able to redeem its tokens here. Always pass an explicit audience that
> identifies *this* STS deployment, e.g.
> `core.getIDToken('https://sts.example.com')` for `actions/github-script`,
> and set the same value in the policy's `audience:` field.

## Per-provider setup

{{< cards >}}
{{< card link="github-actions" title="GitHub Actions" icon="play" subtitle="Most common case, no JWKS host override required" >}}
{{< card link="azure" title="Microsoft Azure" icon="cloud" subtitle="Entra ID workload identity and Azure DevOps Pipelines" >}}
{{< /cards >}}

## How to discover values for any issuer

Two commands, no tooling beyond `curl` and `jq`:

```bash
ISSUER="<the issuer URL>"

# 1. Print the discovery doc (sanity check).
curl -fsS "${ISSUER}/.well-known/openid-configuration" | jq .

# 2. Extract just the jwks_uri host.
curl -fsS "${ISSUER}/.well-known/openid-configuration" \
  | jq -r '.jwks_uri | sub("^https?://"; "") | sub("/.*$"; "")'
```

If the printed host does not equal the issuer's host, that issuer needs an
`oidc.trusted_jwks_hosts` entry.

## Combined example: both providers

```yaml
oidc:
  allowed_issuers:
    - https://token.actions.githubusercontent.com
    - https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0
```

## Validating your config end-to-end

```bash
# 1. Mint a token from your CI provider.
# 2. Decode the token header to confirm 'kid' is set.
echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null | jq .
# 3. Confirm 'iss' matches an entry in allowed_issuers.
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .iss
```

Failure modes to expect:

| Symptom in logs | Cause | Fix |
|---|---|---|
| `issuer "X" not in allowed list` | `iss` not in `allowed_issuers` | Add the issuer URL exactly as it appears in the token. |
| `token header missing kid` | Token has no `kid` | Issuer is misconfigured; this service rejects kid-less tokens. |
| `key "X" not found in JWKS` | Issuer rotated keys | JWKS cache is 1h TTL: wait or restart pods. |
| `jwks_uri host "X" is not the issuer host and not in the trusted JWKS host override` | Issuer's JWKS is on a different host | Add the host to `trusted_jwks_hosts`. |
| `audience mismatch (server required_audience)` | Token's `aud` does not contain `oidc.required_audience` | Pass the right audience to `core.getIDToken('<value>')`. |
| `audience check failed` (per-policy) | Token's `aud` does not match the policy's `audience:` field | Set `audience:` in `.sts.yaml` to match the workflow. |
| `github_identity_invalid` | GitHub identity claims are missing, have wrong types, disagree, or use a legacy subject while immutable format is required | Opt the repository in to immutable subjects, verify owner/repository IDs, or use the visible legacy opt-out temporarily. Correlate `trace_id` for the finite reason. |

## Maintenance: detecting JWKS host drift

Cloud providers occasionally change JWKS hosts. Run this check on a schedule and alert on diff: **do not auto-update**.

```bash
#!/usr/bin/env bash
# scripts/check-jwks-drift.sh
set -euo pipefail

VALUES="${1:-values.yaml}"

for iss in $(yq '.oidc.allowed_issuers[]' "$VALUES"); do
  iss_host=$(echo "$iss" | sed -E 's#^https?://([^/]+).*#\1#')
  observed=$(curl -fsS "${iss}/.well-known/openid-configuration" \
    | jq -r '.jwks_uri | sub("^https?://"; "") | sub("/.*$"; "")') || {
      echo "FAIL: discovery for $iss did not respond"
      continue
    }

  if [ "$observed" = "$iss_host" ]; then
    continue
  fi

  pinned=$(yq ".oidc.trusted_jwks_hosts[\"$iss\"][]" "$VALUES" 2>/dev/null || true)
  if ! grep -qx "$observed" <<< "$pinned"; then
    echo "DRIFT: $iss now publishes JWKS at $observed (not in trusted_jwks_hosts)"
  fi
done
```

Wire it into a weekly CI job; treat any DRIFT line as a security review item.
