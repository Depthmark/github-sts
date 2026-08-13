---
title: Use the GitHub Action
description: "How to integrate github-sts-action in your workflows: prerequisites, OIDC permissions, explicit audience, inputs, output token handling."
weight: 2
translationKey: use-github-action
---

The [github-sts-action](https://github.com/Depthmark/github-sts-action) simplifies OIDC token exchange in GitHub Actions workflows.

## Prerequisites

- A running github-sts instance (see [Deploy with Helm]({{< relref "/integrations/deploy-with-helm" >}}))
- A trust policy defined for your workflow's identity
- `id-token: write` permission on the job

## Quick usage

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: Depthmark/github-sts-action@v0.1.0
        id: sts
        with:
          sts-url: https://sts.example.com
          audience: https://sts.example.com
          scope: ${{ github.repository }}
          identity: ci
      - name: Use the token
        run: |
          git clone https://x-access-token:${{ steps.sts.outputs.token }}@github.com/${{ github.repository }}.git
```

## Inputs

| Input | Required | Description |
|---|---|---|
| `sts-url` | Yes | Base URL of the github-sts instance |
| `audience` | Yes | OIDC audience (must match trust policy `audience:` field) |
| `scope` | Yes | `org/repo` (repo-level) or `org` (org-level) |
| `identity` | Yes | Policy selector (maps to `{base_path}/{app}/{identity}.sts.yaml`) |
| `app` | No | App name (defaults to server default) |
| `extra-params` | No | Extra query parameters appended to the exchange URL |

## Outputs

| Output | Description |
|---|---|
| `token` | The scoped GitHub installation token |
| `scope` | Echo of the requested scope |
| `app` | App name used |
| `identity` | Identity used |
| `permissions` | Granted permissions (JSON) |
| `expires_at` | Token expiry timestamp |

## Security requirements

1. **Pin the action to a specific version tag or full commit SHA.** Never use `@main` in production.
2. **Always set an explicit `audience`.** It must match the `audience:` in your trust policy.
3. **Use `subject` (exact match) in trust policies** whenever possible, not `subject_pattern`.
4. **Grant minimum permissions.** The action only needs `id-token: write`.

## Complete workflow example

```yaml
name: Deploy
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
      deployments: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - uses: Depthmark/github-sts-action@v0.1.0
        id: sts
        with:
          sts-url: https://sts.example.com
          audience: https://sts.example.com
          scope: ${{ github.repository }}
          identity: deploy

      - name: Deploy
        uses: some/deploy-action@v1
        with:
          token: ${{ steps.sts.outputs.token }}
```

## Action reference

For the complete input/output reference, see the [github-sts-action README](https://github.com/Depthmark/github-sts-action).

> Always pin to a specific version tag or commit SHA. Do not use `@main` or a floating tag in production workflows.

## Next

- [End-to-End on Kubernetes]({{< relref "/integrations/end-to-end-github-actions-on-kubernetes" >}}): complete walkthrough
- [Compatibility]({{< relref "/integrations/compatibility" >}}): verified component combinations
- [Trust Policies]({{< relref "/learn/trust-policies" >}}): policy concepts and examples
