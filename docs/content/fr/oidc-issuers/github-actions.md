---
title: GitHub Actions
description: Configurez github-sts pour valider les jetons OIDC émis par GitHub Actions.
weight: 1
translationKey: oidc-issuers-github-actions
translationStatus: pending-review
---

Cas le plus courant pour ce service. Aucune substitution d'hôte JWKS requise.

| Champ | Valeur |
|---|---|
| Émetteur | `https://token.actions.githubusercontent.com` |
| Découverte | `https://token.actions.githubusercontent.com/.well-known/openid-configuration` |
| Hôte `jwks_uri` | `token.actions.githubusercontent.com` (identique à l'émetteur) |
| `kid` dans les jetons | Toujours présent |
| Substitution requise | **Non** |

```yaml
oidc:
  allowed_issuers:
    - https://token.actions.githubusercontent.com
```

Vérifier :

```bash
curl -fsS https://token.actions.githubusercontent.com/.well-known/openid-configuration \
  | jq -r .jwks_uri
# → https://token.actions.githubusercontent.com/.well-known/jwks
```
