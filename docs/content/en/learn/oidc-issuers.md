---
title: OIDC Issuers
description: "Configure GitHub Actions, Azure, GCP, AWS, and generic OIDC issuers: JWKS discovery, audience setup, and validation steps."
weight: 3
translationKey: oidc-issuers
---

This document covers how to configure `github-sts` to validate OIDC tokens from
the major cloud identity providers. The verifier requires every token to:

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

---

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

---

## GitHub Actions

Most common case for this service. No JWKS host override required.

| Field | Value |
|---|---|
| Issuer | `https://token.actions.githubusercontent.com` |
| Discovery | `https://token.actions.githubusercontent.com/.well-known/openid-configuration` |
| `jwks_uri` host | `token.actions.githubusercontent.com` (same as issuer) |
| `kid` in tokens | Always present |
| Override needed | **No** |

```yaml
oidc:
  allowed_issuers:
    - https://token.actions.githubusercontent.com
```

Verify:

```bash
curl -fsS https://token.actions.githubusercontent.com/.well-known/openid-configuration \
  | jq -r .jwks_uri
# → https://token.actions.githubusercontent.com/.well-known/jwks
```

---

## Google Cloud (GCP): Workload Identity / Service Accounts

Two distinct issuer shapes; the JWKS hosts differ.

### Service Account tokens (`iss = https://accounts.google.com`)

| Field | Value |
|---|---|
| Issuer | `https://accounts.google.com` |
| Discovery | `https://accounts.google.com/.well-known/openid-configuration` |
| `jwks_uri` | `https://www.googleapis.com/oauth2/v3/certs` |
| `jwks_uri` host | `www.googleapis.com` (**different from issuer**) |
| `kid` in tokens | Always present |
| Override needed | **Yes** |

```yaml
oidc:
  allowed_issuers:
    - https://accounts.google.com
  trusted_jwks_hosts:
    https://accounts.google.com:
      - www.googleapis.com
```

### Service Account self-issued tokens (`iss = https://<sa-email>` or numeric ID)

These are rarer; tokens minted with `iss` set to the service-account email use
their own discovery doc on `accounts.google.com`. Same override rule applies : 
JWKS resolves to `www.googleapis.com`.

---

## AWS

### IAM Roles for Service Accounts (IRSA): EKS workloads

| Field | Value |
|---|---|
| Issuer | `https://oidc.eks.<region>.amazonaws.com/id/<CLUSTER_OIDC_ID>` |
| `jwks_uri` host | `oidc.eks.<region>.amazonaws.com` (same as issuer) |
| `kid` in tokens | Always present |
| Override needed | **No** |

```bash
aws eks describe-cluster --name <cluster-name> --region <region> \
  --query "cluster.identity.oidc.issuer" --output text
```

```yaml
oidc:
  allowed_issuers:
    - https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E
```

> One issuer per cluster. The OIDC ID is unique to each EKS cluster.

### Amazon Cognito User Pools

| Field | Value |
|---|---|
| Issuer | `https://cognito-idp.<region>.amazonaws.com/<USER_POOL_ID>` |
| Override needed | **No** |

---

## Microsoft Azure: Entra ID (formerly Azure AD)

### Workload Identity / App tokens (v2.0)

| Field | Value |
|---|---|
| Issuer | `https://login.microsoftonline.com/<TENANT_ID>/v2.0` |
| Discovery | `https://login.microsoftonline.com/<TENANT_ID>/v2.0/.well-known/openid-configuration` |
| `jwks_uri` host | `login.microsoftonline.com` (same as issuer) |
| Override needed | **No** |

```yaml
oidc:
  allowed_issuers:
    - https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0
```

### Azure DevOps Pipelines (workload identity federation)

| Field | Value |
|---|---|
| Issuer | `https://vstoken.dev.azure.com/<ORGANIZATION_ID>` |
| Override needed | **No** |

---

## Combined example: all four providers

```yaml
oidc:
  allowed_issuers:
    - https://token.actions.githubusercontent.com
    - https://accounts.google.com
    - https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E
    - https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0
  trusted_jwks_hosts:
    https://accounts.google.com:
      - www.googleapis.com
```

---

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
