# OIDC Issuer Configuration

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
> That default is **not safe** for an STS — every workflow in the org would be
> able to redeem its tokens here. Always pass an explicit audience that
> identifies *this* STS deployment, e.g.
> `core.getIDToken('https://sts.example.com')` for `actions/github-script`,
> and set the same value in the policy's `audience:` field.

Section headers below are per-provider. Each section gives:
- The discovery URL.
- The expected `jwks_uri` host.
- A working `values.yaml` snippet.
- How to verify the configuration with `curl`.

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
  require_immutable_subject_claims: true # secure default
  # trusted_jwks_hosts: not needed
```

For GitHub.com, github-sts requires signed string claims for
`repository_owner`, `repository_owner_id`, `repository`, and `repository_id`.
It cross-checks these values against the token subject before audience, replay,
or policy lookup.

By default the subject must contain immutable IDs:

```text
repo:OWNER@OWNER-ID/REPO@REPO-ID:ref:refs/heads/BRANCH
```

Repositories created before July 15, 2026 retain the previous name-only format
until they opt in through GitHub's organization/repository Actions OIDC setting
or REST API. Set `require_immutable_subject_claims: false` only as an explicit
legacy migration posture. Separate immutable ID claims remain mandatory. This
feature applies only to GitHub.com and is not available on GitHub Enterprise
Server.

### Getting the immutable owner and repository IDs

Trust policies (`github.sources[]` / `github.target`, see
[Configuration → Trust policies](configuration.md#trust-policies)) and
enterprise cross-org exceptions are keyed on numeric `owner_id` /
`repository_id`, not names. Look them up with the GitHub API before writing
the policy — no token exchange required:

```bash
# Both source and target repos: owner_id + repository_id in one call.
gh api repos/OWNER/REPO --jq '{owner_id: (.owner.id | tostring), repository_id: (.id | tostring)}'
# → {"owner_id":"123456","repository_id":"456789"}
```

Without `gh`, the equivalent `curl` (a GitHub token is only needed for
private repos):

```bash
curl -fsS -H "Authorization: Bearer $GITHUB_TOKEN" \
  "https://api.github.com/repos/OWNER/REPO" \
  | jq '{owner_id: (.owner.id | tostring), repository_id: (.id | tostring)}'
```

Trust-policy fields are strings (`"123456"`, not `123456`) — quote the values
from `jq` output when pasting into YAML.

Once a workflow has opted in to immutable subjects, confirm the minted OIDC
token actually carries the same IDs (see
[Troubleshooting → Debugging an exchange end-to-end](troubleshooting.md#debugging-an-exchange-end-to-end)
for the decode command):

```bash
echo "$OIDC_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null \
  | jq '{sub, repository_owner_id, repository_id}'
```

If `repository_owner_id` / `repository_id` are absent from the decoded token,
the repository has not opted in to immutable claims yet — opt in via the
repository or organization Actions "OIDC customization" setting (or the
equivalent REST API) before relying on `github.sources[]` / `github.target`
matches.

Verify:

```bash
curl -fsS https://token.actions.githubusercontent.com/.well-known/openid-configuration \
  | jq -r .jwks_uri
# → https://token.actions.githubusercontent.com/.well-known/jwks
```

---

## Google Cloud (GCP) — Workload Identity / Service Accounts

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
    # Google publishes JWKS at googleapis.com, not at the issuer host.
    # See https://accounts.google.com/.well-known/openid-configuration
    https://accounts.google.com:
      - www.googleapis.com
```

### Service Account self-issued tokens (`iss = https://<sa-email>` or numeric ID)

These are rarer; tokens minted with `iss` set to the service-account email use
their own discovery doc on `accounts.google.com`. Same override rule applies —
JWKS resolves to `www.googleapis.com`. Use the discovery command above against
the actual `iss` value to confirm before configuring.

### Verify

```bash
curl -fsS https://accounts.google.com/.well-known/openid-configuration \
  | jq -r .jwks_uri
# → https://www.googleapis.com/oauth2/v3/certs
```

---

## AWS

AWS has multiple OIDC sources; treat them separately because they differ.

### IAM Roles for Service Accounts (IRSA) — EKS workloads

Each EKS cluster issues its own OIDC tokens; the issuer is the cluster's OIDC
provider URL, hosted on a per-region S3 bucket.

| Field | Value |
|---|---|
| Issuer | `https://oidc.eks.<region>.amazonaws.com/id/<CLUSTER_OIDC_ID>` |
| `jwks_uri` host | `oidc.eks.<region>.amazonaws.com` (same as issuer) |
| `kid` in tokens | Always present |
| Override needed | **No** |

Find your cluster's issuer:

```bash
aws eks describe-cluster --name <cluster-name> --region <region> \
  --query "cluster.identity.oidc.issuer" --output text
```

```yaml
oidc:
  allowed_issuers:
    - https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E
  # trusted_jwks_hosts: not needed
```

> ⚠️ **One issuer per cluster.** The OIDC ID is unique to each EKS cluster.
> If you target multiple clusters, list each issuer URL.

### Amazon Cognito User Pools

| Field | Value |
|---|---|
| Issuer | `https://cognito-idp.<region>.amazonaws.com/<USER_POOL_ID>` |
| `jwks_uri` host | `cognito-idp.<region>.amazonaws.com` (same as issuer) |
| `kid` in tokens | Always present |
| Override needed | **No** |

```yaml
oidc:
  allowed_issuers:
    - https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEfGhI
```

### AWS STS / Federation tokens

AWS STS does not publish OIDC tokens consumable here — it consumes OIDC tokens
to mint AWS credentials. Not applicable to this service.

---

## Microsoft Azure — Entra ID (formerly Azure AD)

Two relevant token shapes.

### Workload Identity / App tokens (v2.0)

| Field | Value |
|---|---|
| Issuer | `https://login.microsoftonline.com/<TENANT_ID>/v2.0` |
| Discovery | `https://login.microsoftonline.com/<TENANT_ID>/v2.0/.well-known/openid-configuration` |
| `jwks_uri` host | `login.microsoftonline.com` (same as issuer) |
| `kid` in tokens | Always present |
| Override needed | **No** |

```yaml
oidc:
  allowed_issuers:
    - https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0
```

> ⚠️ **Tenant ID is part of the issuer.** Multi-tenant apps must list each
> tenant's issuer URL, or use `https://login.microsoftonline.com/common/v2.0`
> (read the security implications before doing so — `common` accepts tokens
> from any Microsoft account).

### Azure DevOps Pipelines (workload identity federation)

| Field | Value |
|---|---|
| Issuer | `https://vstoken.dev.azure.com/<ORGANIZATION_ID>` |
| `jwks_uri` host | `vstoken.dev.azure.com` (same as issuer) |
| `kid` in tokens | Always present |
| Override needed | **No** |

```yaml
oidc:
  allowed_issuers:
    - https://vstoken.dev.azure.com/00000000-0000-0000-0000-000000000000
```

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

GitHub, AWS EKS, and Azure all share host with their JWKS endpoint and need no
override. Google is the only common provider that splits hosts.

---

## Validating your config end-to-end

After deploying, confirm the verifier accepts a real token:

```bash
# 1. Mint a token from your CI provider (example: GitHub Actions).
#    Most providers support `id-token: write` style permissions.

# 2. Decode the token header to confirm `kid` is set.
echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null | jq .
# → { "alg": "RS256", "kid": "...", "typ": "JWT" }

# 3. Confirm `iss` matches an entry in allowed_issuers.
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .iss

# 4. POST to /exchange and read the response.
```

Failure modes to expect:

| Symptom in logs | Cause | Fix |
|---|---|---|
| `issuer "X" not in allowed list` | `iss` not in `allowed_issuers` | Add the issuer URL exactly as it appears in the token. |
| `token header missing kid` | Token has no `kid` | Issuer is misconfigured; this service rejects kid-less tokens. |
| `key "X" not found in JWKS` | Issuer rotated keys | JWKS cache is 1 h TTL — wait or restart pods. |
| `jwks_uri host "X" is not the issuer host and not in the trusted JWKS host override` | Issuer's JWKS is on a different host | Add the host to `trusted_jwks_hosts` after verifying with curl. |
| `OIDC discovery returned 302` (or similar 3xx) | Issuer's discovery doc redirects | Investigate — redirects are intentionally not followed. The issuer URL itself may be wrong. |
| `audience mismatch (server required_audience)` | Token's `aud` does not contain `oidc.required_audience` | Either pass the right audience to the workflow (`core.getIDToken('<value>')`) or update `required_audience` in the server config. |
| `audience check failed` (per-policy) | Token's `aud` does not match the policy's `audience:` field, or the policy was loaded without one | Set `audience:` in the `.sts.yaml` to the value the workflow requests. The field is mandatory at parse time — a policy without it never loads. |
| `github_identity_invalid` | GitHub identity claims are missing, have wrong types, disagree, or use a legacy subject while immutable format is required | Opt the repository in to immutable subjects, verify owner/repository IDs, or use the visible legacy opt-out temporarily. Correlate `trace_id` for the finite reason. |

---

## Maintenance: detecting JWKS host drift

Cloud providers occasionally change JWKS hosts (CDN migrations, regional
changes). Run this check on a schedule and alert on diff — **do not
auto-update**, since auto-update would defeat the pin.

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

Wire it into a weekly CI job; treat any DRIFT line as a security review item,
not a rubber-stamp config bump.
