---
title: Install the App
description: Install the GitHub App on the organization or repositories the issued tokens should ever touch.
weight: 3
translationKey: get-started-install-the-app
---

A GitHub App has permissions (what it's *capable* of), and an installation (*where* it can act).
Both bound the tokens github-sts can issue.

## Install on specific repositories, not the whole org

From the App's settings page, click **Install App**, choose the organization, then select
**Only select repositories** and pick the exact repositories your workloads need. This keeps the
App's blast radius equal to what's actually in use, independent of anything a trust policy says.

Choosing **All repositories** means every future repo in the org is automatically in scope. Avoid
this unless that is genuinely the intent.

## Multiple environments, multiple installations

If staging and production workloads should never be able to redeem each other's tokens, use
separate GitHub Apps (and separate installations) per environment rather than one App installed
everywhere. github-sts supports [multiple GitHub Apps](../../reference/configuration/) in a single
deployment for exactly this case.

## Confirm the installation

```bash
curl -fsS -H "Authorization: Bearer $JWT" \
  https://api.github.com/app/installations | jq '.[].account.login'
```

(`$JWT` here is a short-lived App JWT signed with the private key. See
[GitHub's authentication docs](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app) if you want to verify this by hand. In normal
operation, github-sts does this signing for you.)

## Next

[Generate a token](../generate-a-token/): write a trust policy and call `/sts/exchange`.
