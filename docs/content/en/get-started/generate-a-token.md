---
title: Generate a token
description: Write a trust policy and exchange an OIDC token for a scoped GitHub installation token.
weight: 4
translationKey: get-started-generate-a-token
---

With the App configured and installed, the last two pieces are a **trust policy** (who may ask,
and for what) and the **OIDC token** an identity presents to prove who it is.

## Write a trust policy

Trust policies live **in the target repository** at `.github/sts/{app}/{identity}.sts.yaml`. For
`app=default` and `identity=ci` in `myorg/myrepo`, that's:

```
myorg/myrepo/.github/sts/default/ci.sts.yaml
```

Minimal example for a GitHub Actions workflow on `main`:

```yaml
issuer: https://token.actions.githubusercontent.com
claim_pattern:
  ref: refs/heads/main
audience: https://sts.example.com
github:
  sources:
    - owner_id: "123456"
      repository_id: "456789"
  target:
    owner_id: "123456"
    repository_id: "456789"
permissions:
  contents: read
  pull_requests: write
```

Replace the example IDs with `myorg`/`myrepo`'s immutable owner and repository IDs. See [OIDC Issuers → Getting the immutable owner and repository IDs](../../oidc-issuers/github-actions/#getting-the-immutable-owner-and-repository-ids). GitHub.com source repositories must opt in to immutable subject claims unless the server's explicit degraded migration posture is temporarily selected.

> **`audience` is mandatory**, and it must match the audience the workload requests in its OIDC
> token. It's what ties a token to *this* github-sts deployment and no other. See
> [OIDC Issuers](../../oidc-issuers/) for how each provider's tokens are validated. `github.sources[]`/`github.target` pin the policy to exact, immutable repositories so a rename or ownership transfer can't silently reauthorize a different repo.

## Request the OIDC token

From a GitHub Actions workflow, request an OIDC token with an explicit audience:

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - name: Obtain OIDC token
        uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c379ccdee # v7.0.1
        id: oidc
        with:
          script: |
            const token = await core.getIDToken('https://sts.example.com')
            core.setOutput('token', token)
```

Scope `id-token: write` to the job that needs it, not the whole workflow.

## Exchange it

```bash
curl -H "Authorization: Bearer $OIDC_TOKEN" \
  "https://sts.example.com/sts/exchange?scope=myorg/myrepo&app=default&identity=ci"
```

```json
{
  "token": "ghs_xxxxxxxxxxxxxxxxxxxx",
  "expires_in": 3600,
  "scope": "myorg/myrepo",
  "app": "default",
  "identity": "ci",
  "permissions": {
    "contents": "read",
    "pull_requests": "write"
  }
}
```

The `ghs_…` token is a standard GitHub App installation token, scoped to the resolved target
repository ID and the permissions the policy declared. `expires_in` is how many seconds it has
left, so a long-running job can refresh on time instead of assuming a lifetime. See
[the API reference]({{< relref "/reference/api" >}}) for when the field is absent.
For a drop-in wrapper around this exchange in Actions, see
[the GitHub Action quickstart]({{< relref "/integrations/github-action/quickstart" >}}). The manual `curl` form above works
from any CI system that can produce an OIDC token.

## Security checklist

- [ ] `id-token: write` is scoped to the specific job, not the entire workflow
- [ ] Audience is explicit and matches the trust policy
- [ ] The trust policy uses `subject` (exact match) whenever possible, not `subject_pattern`
- [ ] Permissions in the trust policy are the minimum required
- [ ] The github-sts URL uses HTTPS in production

## Next

[Monitor usage](../../integrations/monitor-usage/): read the metrics and audit log to confirm what was issued.
