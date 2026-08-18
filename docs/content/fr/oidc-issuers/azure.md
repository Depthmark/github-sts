---
title: Microsoft Azure
description: Configurez github-sts pour valider les jetons OIDC d'Entra ID et d'Azure DevOps Pipelines.
weight: 2
translationKey: oidc-issuers-azure
translationStatus: pending-review
---

Entra ID (anciennement Azure AD).

## Jetons Workload Identity / App (v2.0)

| Champ | Valeur |
|---|---|
| Émetteur | `https://login.microsoftonline.com/<TENANT_ID>/v2.0` |
| Découverte | `https://login.microsoftonline.com/<TENANT_ID>/v2.0/.well-known/openid-configuration` |
| Hôte `jwks_uri` | `login.microsoftonline.com` (identique à l'émetteur) |
| Substitution requise | **Non** |

```yaml
oidc:
  allowed_issuers:
    - https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0
```

## Azure DevOps Pipelines (fédération d'identité de charge de travail)

| Champ | Valeur |
|---|---|
| Émetteur | `https://vstoken.dev.azure.com/<ORGANIZATION_ID>` |
| Substitution requise | **Non** |
