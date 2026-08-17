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
```

Verify:

```bash
curl -fsS https://token.actions.githubusercontent.com/.well-known/openid-configuration \
  | jq -r .jwks_uri
# → https://token.actions.githubusercontent.com/.well-known/jwks
```
