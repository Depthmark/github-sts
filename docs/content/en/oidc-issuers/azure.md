---
title: Microsoft Azure
description: Configure github-sts to validate OIDC tokens from Entra ID and Azure DevOps Pipelines.
weight: 2
translationKey: oidc-issuers-azure
---

Entra ID (formerly Azure AD).

## Workload Identity / App tokens (v2.0)

| Field | Value |
|---|---|
| Issuer | `https://login.microsoftonline.com/<TENANT_ID>/v2.0` |
| Discovery | `https://login.microsoftonline.com/<TENANT_ID>/v2.0/.well-known/openid-configuration` |
| `jwks_uri` host | `login.microsoftonline.com` (same as issuer) |
| Override needed | **No** |

```yaml
oidc:
  allowed_issuers:
    - https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0
```

## Azure DevOps Pipelines (workload identity federation)

| Field | Value |
|---|---|
| Issuer | `https://vstoken.dev.azure.com/<ORGANIZATION_ID>` |
| Override needed | **No** |
