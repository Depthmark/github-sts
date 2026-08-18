---
title: GitHub Actions
description: Configure github-sts to validate OIDC tokens issued by GitHub Actions.
weight: 1
translationKey: oidc-issuers-github-actions
---

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
[Trust Policies]({{< relref "/concepts/trust-policies" >}})) and enterprise
cross-org exceptions are keyed on numeric `owner_id` / `repository_id`, not
names. Look them up with the GitHub API before writing the policy — no token
exchange required:

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
[Troubleshooting → Debugging an exchange end-to-end]({{< relref "/operations/troubleshooting#debugging-an-exchange-end-to-end" >}})
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
