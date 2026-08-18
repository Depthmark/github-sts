---
title: End-to-End GitHub Actions on Kubernetes
description: "Complete supported workflow: install Helm chart, configure github-sts, create a trust policy, use the Action, exchange a token, and verify."
weight: 3
translationKey: end-to-end-github-actions-on-kubernetes
---

This guide walks through a complete deployment: Helm install, trust policy creation, GitHub Action integration, token exchange, and verification.

## Overview

You will:

1. Install github-sts on Kubernetes via Helm
2. Configure a trust policy for your workflow
3. Run a workflow that uses the github-sts-action
4. Exchange an OIDC token for a scoped GitHub installation token
5. Verify audit logs and metrics

## 1. Install github-sts

```bash
helm repo add depthmark https://depthmark.github.io/charts
helm install github-sts depthmark/github-sts \
  --namespace github-sts --create-namespace \
  --version v0.1.0 \
  --set apps.default.appId=123456 \
  --set-file apps.default.privateKey=/path/to/private-key.pem \
  --set oidc.requiredAudience=https://sts.example.com \
  --set oidc.allowedIssuers[0]=https://token.actions.githubusercontent.com
```

Verify:

```bash
kubectl get pods -n github-sts
kubectl logs -n github-sts deploy/github-sts
```

## 2. Create a trust policy

In your target repository, create `.github/sts/default/ci.sts.yaml`:

```yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:myorg/myrepo:ref:refs/heads/main
audience: https://sts.example.com
permissions:
  contents: read
  pull_requests: write
```

Commit and push.

## 3. Configure the workflow

Create `.github/workflows/deploy.yml`:

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
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - uses: Depthmark/github-sts-action@v0.1.0
        id: sts
        with:
          sts-url: https://sts.example.com
          audience: https://sts.example.com
          scope: ${{ github.repository }}
          identity: ci

      - name: Verify token
        run: |
          echo "Scope: ${{ steps.sts.outputs.scope }}"
          echo "Permissions: ${{ steps.sts.outputs.permissions }}"

      - name: Use the token
        run: |
          gh repo view ${{ github.repository }} --json name
        env:
          GH_TOKEN: ${{ steps.sts.outputs.token }}
```

## 4. Run the workflow

Push to the `main` branch. The workflow will:

1. Request an OIDC token with audience `https://sts.example.com`
2. Send it to github-sts's `/sts/exchange` endpoint
3. Receive a scoped installation token
4. Use it to access the repository

## 5. Verify

### Check the action output

The action outputs the token's scope, app, identity, and permissions.

### Check server audit logs

```bash
kubectl logs -n github-sts deploy/github-sts | grep "result.success"
```

Expected fields:
- `result: success`
- `issuer: https://token.actions.githubusercontent.com`
- `subject: repo:myorg/myrepo:ref:refs/heads/main`

### Check metrics

```bash
# Successful exchange
curl -s https://sts.example.com/metrics | grep githubsts_token_exchanges_total{result=\"success\"}

# Token issued
curl -s https://sts.example.com/metrics | grep githubsts_github_tokens_issued_total

# No errors
curl -s https://sts.example.com/metrics | grep githubsts_oidc_validation_errors_total
```

### Verify token revocation

Tokens expire automatically after one hour. You can also manually revoke:

```yaml
- name: Revoke token at job end
  if: always()
  run: |
    curl -X DELETE https://api.github.com/installation/token \
      -H "Authorization: Bearer ${{ steps.sts.outputs.token }}"
```

## Failure scenarios to test

### 1. Missing audience

Remove `audience:` from the trust policy. The policy fails to parse, and the exchange returns `502` with `upstream_error`.

### 2. Wrong audience

Keep `audience:` in the policy but request a different audience in the workflow. The exchange returns `403` with `audience_mismatch`.

### 3. Wrong branch

Change the workflow to trigger on a branch other than `main`. The exchange should fail with `policy_denied` because `subject` doesn't match.

### 4. Wrong identity

Change `identity: ci` to `identity: unknown`. The exchange should fail with `policy_not_found`.

## Troubleshooting

See [Troubleshooting]({{< relref "/operations/troubleshooting" >}}) for the complete diagnostic guide.

## Next

- [Compatibility]({{< relref "/integrations/compatibility" >}}): verified component combinations
- [Use the GitHub Action]({{< relref "/integrations/use-github-action" >}}): action input/output reference
- [Deploy with Helm]({{< relref "/integrations/deploy-with-helm" >}}): complete Helm values reference
