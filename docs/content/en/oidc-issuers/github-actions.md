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
names. Look them up with the GitHub API before writing the policy: no token
exchange required.

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

Trust-policy fields are strings (`"123456"`, not `123456`). Quote the values
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
the repository has not opted in to immutable claims yet. Opt in via the
repository or organization Actions "OIDC customization" setting (or the
equivalent REST API) before relying on `github.sources[]` / `github.target`
matches.

Verify:

```bash
curl -fsS https://token.actions.githubusercontent.com/.well-known/openid-configuration \
  | jq -r .jwks_uri
# → https://token.actions.githubusercontent.com/.well-known/jwks
```

## Accept tokens from a GitHub.com enterprise issuer {#enterprise-issuer}

Let one GitHub Enterprise Cloud enterprise reach chosen Apps through its own issuer. An enterprise owner can make GitHub add the enterprise slug to `iss`. A policy that names this issuer then matches tokens from that enterprise only, not from every GitHub.com repository.

**1. Declare the issuer.** List it in both places, and name the Apps it may reach:

```yaml
oidc:
  allowed_issuers:
    - https://token.actions.githubusercontent.com
    - https://token.actions.githubusercontent.com/myorg-enterprise
  github_issuers:
    - issuer: https://token.actions.githubusercontent.com/myorg-enterprise
      apps:
        - deploy
```

The issuer shares the default issuer's keys on the same host, so it needs no `trusted_jwks_hosts` entry. Keep the default issuer in `allowed_issuers` until no workload uses it.

**2. Write the trust policy for that issuer.** A declared issuer needs the `github` block, as the default issuer does:

```yaml
issuer: https://token.actions.githubusercontent.com/myorg-enterprise
audience: https://sts.example.com
subject: repo:myorg@123456/myrepo@456789:ref:refs/heads/main
github:
  sources:
    - owner_id: "123456"
      repository_id: "456789"
  target:
    owner_id: "123456"
    repository_id: "456789"
permissions:
  contents: read
```

A policy names exactly one issuer. Once GitHub switches the enterprise, a policy that still names the default issuer denies its tokens with `policy_denied`, so plan steps 2 and 3 for the same window.

**3. Turn the issuer on in GitHub.** An enterprise owner runs this with a classic personal access token or an OAuth app token that has the `admin:enterprise` scope. GitHub answers `204`:

```bash
gh api --method PUT /enterprises/myorg-enterprise/actions/oidc/customization/issuer \
  -F include_enterprise_slug=true
```

**4. Confirm with a real token.** Decode one from a workflow run. Do not rely on the discovery document for this: GitHub answers `200` for any slug, including one that does not exist.

```bash
echo "$OIDC_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null \
  | jq '{iss, sub, repository_owner_id, repository_id}'
```

### What github-sts enforces for a declared issuer

| Control | Behavior | Failure |
|---|---|---|
| Identity | The same signed claim checks as the default issuer, before audience, replay or policy work. | `github_identity_invalid` |
| Immutable subject | Always required. `require_immutable_subject_claims: false` applies to the default issuer only, so it cannot relax a declared one. Repositories created before July 15, 2026 must opt in first. | `github_identity_invalid` |
| App scope | The App resolved for the request must be listed under `apps`. github-sts denies the token before any GitHub call, whatever the policy says. | `issuer_not_enabled` |
| Source and target | The policy must list the exact `github.sources[]` and `github.target` IDs, as for the default issuer. | `policy_denied` |
| Configuration | Startup fails and names the field for an issuer of another form, an unknown or missing App, a duplicate, or an issuer absent from `allowed_issuers`. | Server does not start |

An enterprise issuer listed only in `allowed_issuers` stays a generic issuer. Its tokens get no GitHub identity checks, its policies cannot use the `github` block, and the server logs a warning at startup. Declare it to close that gap.

Rego receives the enterprise URL in `source_identity.issuer`. A baseline that pins the default issuer, as `policies/example_enterprise_baseline.rego` does, denies these tokens until you add the issuer to it.

### Other GitHub issuers

Only the first row of this table can be declared. `oidc.github_issuers` refuses the others at startup, because their IDs or subjects differ from GitHub.com's. Listed in `allowed_issuers` alone, they stay generic issuers with no GitHub identity checks.

| Product | Issuer | Declared in `oidc.github_issuers` |
|---|---|---|
| GitHub Enterprise Cloud on GitHub.com | `https://token.actions.githubusercontent.com/<enterprise-slug>` | Yes |
| GitHub Enterprise Cloud on GHE.com | `https://token.actions.<subdomain>.ghe.com/<subdomain>` | No: the enterprise has its own instance and IDs |
| GitHub Enterprise Server | `https://<hostname>/_services/token` | No: IDs come from another instance, and it has no immutable subject |
