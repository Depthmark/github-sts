---
title: GitHub Actions Integration
description: Complete secure GitHub Actions integration using OIDC id-token, explicit audience binding, a trust policy, and a token exchange.
weight: 2
translationKey: github-actions
---

This guide walks through a complete, secure GitHub Actions integration with github-sts.

## Overview

A GitHub Actions workflow can authenticate to github-sts using OIDC and receive a scoped installation token: no secrets, no PATs. The workflow:

1. Requests an OIDC token with `id-token: write`
2. Passes an explicit audience to `core.getIDToken()`
3. Sends the token to github-sts's `/sts/exchange` endpoint
4. Receives a scoped GitHub installation token

## Prerequisites

- A running github-sts instance (see [Getting Started]({{< relref "/learn/getting-started" >}}))
- A GitHub App installed on your target org/repos
- A trust policy defined in the target repository

## Step 1: Grant OIDC permissions

Add `id-token: write` to your workflow or job:

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
```

## Step 2: Request an OIDC token

Use the `actions/github-script` action or the `github-sts-action` to obtain an OIDC token with an explicit audience:

```yaml
- name: Obtain OIDC token
  uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c379ccdee # v7.0.1
  id: oidc
  with:
    script: |
      const token = await core.getIDToken('https://sts.example.com')
      core.setOutput('token', token)
```

> **Audience is mandatory.** The value passed to `core.getIDToken()` must match the `audience:` field in your trust policy. See [Trust Policies]({{< relref "/learn/trust-policies" >}}) for details.

## Step 3: Exchange the token

```yaml
- name: Exchange OIDC token for GitHub token
  run: |
    RESPONSE=$(curl -s -H "Authorization: Bearer ${{ steps.oidc.outputs.token }}" \
      "https://sts.example.com/sts/exchange?scope=${{ github.repository }}&app=default&identity=ci")
    echo "TOKEN=$(echo $RESPONSE | jq -r .token)" >> $GITHUB_ENV
- name: Use the token
  run: |
    git clone https://x-access-token:${{ env.TOKEN }}@github.com/${{ github.repository }}.git
```

## Step 4: Define the trust policy

Create `.github/sts/default/ci.sts.yaml` in your target repository:

```yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:myorg/myrepo:ref:refs/heads/main
audience: https://sts.example.com
permissions:
  contents: read
  pull_requests: write
```

## Complete workflow example

```yaml
name: CI
on:
  push:
    branches: [main]

jobs:
  build:
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

      - name: Exchange for GitHub token
        run: |
          RESPONSE=$(curl -fsS -H "Authorization: Bearer ${{ steps.oidc.outputs.token }}" \
            "https://sts.example.com/sts/exchange?scope=${{ github.repository }}&app=default&identity=ci")
          echo "GH_TOKEN=$(echo $RESPONSE | jq -r .token)" >> $GITHUB_ENV

      - name: Use the token
        run: |
          echo "Got a scoped token with permissions: ${{ env.GH_TOKEN }}"
```

## Using the github-sts-action

For a simpler integration, use the [github-sts-action](https://github.com/Depthmark/github-sts-action):

```yaml
- uses: Depthmark/github-sts-action@v0.1.0
  id: sts
  with:
    sts-url: https://sts.example.com
    audience: https://sts.example.com
    scope: ${{ github.repository }}
    identity: ci
- run: echo "Token: ${{ steps.sts.outputs.token }}"
```

See [Use the GitHub Action]({{< relref "/integrations/use-github-action" >}}) for the full reference.

## Security checklist

- [ ] `id-token: write` is scoped to the specific job, not the entire workflow
- [ ] Audience is explicit and matches the trust policy
- [ ] The trust policy uses `subject` (exact match) whenever possible, not `subject_pattern`
- [ ] Permissions in the trust policy are the minimum required
- [ ] The STS URL uses HTTPS in production
