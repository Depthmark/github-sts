---
title: Configure a GitHub App
description: Create the GitHub App github-sts will use to mint installation tokens, set its permissions, and generate a private key.
weight: 2
translationKey: get-started-configure-github-app
---

github-sts issues tokens by authenticating as a **GitHub App**, then requesting an installation
token scoped to exactly what a trust policy allows. Before anything else, that App has to exist.

## 1. Create the App

In the org or account that will own the App: **Settings → Developer settings → GitHub Apps → New GitHub App**.

- **GitHub App name**: anything identifiable, e.g. `github-sts-<environment>`.
- **Homepage URL**: any valid URL. It is not used at runtime.
- **Webhook**: uncheck **Active**. github-sts does not consume webhooks.

## 2. Set permissions

Grant only the repository/organization permissions your trust policies will actually issue.
A common starting set:

| Permission | Access | Why |
|---|---|---|
| Contents | Read and write | Clone, push, create releases |
| Pull requests | Read and write | Open, comment, merge PRs |
| Metadata | Read-only | Required by GitHub for all Apps |

> **This is your ceiling, not your policy.** Whatever you grant here bounds the maximum any trust
> policy can ever issue. A policy cannot request a permission the App itself does not have. Start
> narrow and add permissions when a real workload needs them, not speculatively.

## 3. Generate a private key

On the App's settings page, under **Private keys**, click **Generate a private key**. GitHub
downloads a `.pem` file. This is the only copy, so store it in a secret manager, not in the repo.

Note the **App ID** shown at the top of the same page. You will need it alongside the private key.

## Next

[Install the App](../install-the-app/) on the organization or repositories the tokens will touch.
