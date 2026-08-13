---
title: Émetteurs OIDC
description: "Configurez GitHub Actions, Azure, GCP, AWS et les émetteurs OIDC génériques : découverte JWKS, configuration de l'audience et étapes de validation."
weight: 3
translationKey: oidc-issuers
translationStatus: pending-review
---

Ce document explique comment configurer `github-sts` pour valider les jetons OIDC des
principaux fournisseurs d'identité cloud. Le vérificateur exige que chaque jeton :

1. Possède une revendication `iss` présente dans `oidc.allowed_issuers`.
2. Porte un `kid` dans l'en-tête JWT correspondant à une clé du JWKS de l'émetteur.
3. Résolve un `jwks_uri` (via la découverte OIDC) dont l'hôte correspond soit à
   l'hôte de l'émetteur, soit est accepté via `oidc.trusted_jwks_hosts`.
4. Porte une revendication `aud` correspondant au champ `audience:` de la politique
   (obligatoire dans chaque politique) et, si défini, à `oidc.required_audience` au niveau du serveur.

> **Piège de l'audience.** La plupart des bibliothèques OIDC définissent `aud` par défaut à une valeur utile
> uniquement pour l'émetteur (par exemple, GitHub Actions utilise l'URL du dépôt du workflow par défaut).
> Ce défaut n'est **pas sûr** pour un STS: chaque workflow de l'organisation pourrait
> alors échanger ses jetons ici. Transmettez toujours une audience explicite qui
> identifie *ce* déploiement STS, par exemple
> `core.getIDToken('https://sts.example.com')` pour `actions/github-script`,
> et définissez la même valeur dans le champ `audience:` de la politique.

---

## Comment découvrir les valeurs pour n'importe quel émetteur

Deux commandes, sans autre outil que `curl` et `jq` :

```bash
ISSUER="<the issuer URL>"

# 1. Print the discovery doc (sanity check).
curl -fsS "${ISSUER}/.well-known/openid-configuration" | jq .

# 2. Extract just the jwks_uri host.
curl -fsS "${ISSUER}/.well-known/openid-configuration" \
  | jq -r '.jwks_uri | sub("^https?://"; "") | sub("/.*$"; "")'
```

Si l'hôte affiché ne correspond pas à l'hôte de l'émetteur, cet émetteur nécessite une
entrée `oidc.trusted_jwks_hosts`.

---

## GitHub Actions

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

---

## Google Cloud (GCP): Workload Identity / Comptes de service

Deux formes d'émetteur distinctes ; les hôtes JWKS diffèrent.

### Jetons de compte de service (`iss = https://accounts.google.com`)

| Champ | Valeur |
|---|---|
| Émetteur | `https://accounts.google.com` |
| Découverte | `https://accounts.google.com/.well-known/openid-configuration` |
| `jwks_uri` | `https://www.googleapis.com/oauth2/v3/certs` |
| Hôte `jwks_uri` | `www.googleapis.com` (**différent de l'émetteur**) |
| `kid` dans les jetons | Toujours présent |
| Substitution requise | **Oui** |

```yaml
oidc:
  allowed_issuers:
    - https://accounts.google.com
  trusted_jwks_hosts:
    https://accounts.google.com:
      - www.googleapis.com
```

### Jetons auto-émis de compte de service (`iss = https://<sa-email>` ou ID numérique)

Plus rares ; les jetons émis avec `iss` défini à l'adresse e-mail du compte de service utilisent
leur propre document de découverte sur `accounts.google.com`. La même règle de substitution s'applique : 
le JWKS se résout vers `www.googleapis.com`.

---

## AWS

### IAM Roles for Service Accounts (IRSA): charges de travail EKS

| Champ | Valeur |
|---|---|
| Émetteur | `https://oidc.eks.<region>.amazonaws.com/id/<CLUSTER_OIDC_ID>` |
| Hôte `jwks_uri` | `oidc.eks.<region>.amazonaws.com` (identique à l'émetteur) |
| `kid` dans les jetons | Toujours présent |
| Substitution requise | **Non** |

```bash
aws eks describe-cluster --name <cluster-name> --region <region> \
  --query "cluster.identity.oidc.issuer" --output text
```

```yaml
oidc:
  allowed_issuers:
    - https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E
```

> Un émetteur par cluster. L'ID OIDC est unique à chaque cluster EKS.

### Amazon Cognito User Pools

| Champ | Valeur |
|---|---|
| Émetteur | `https://cognito-idp.<region>.amazonaws.com/<USER_POOL_ID>` |
| Substitution requise | **Non** |

---

## Microsoft Azure: Entra ID (anciennement Azure AD)

### Jetons Workload Identity / App (v2.0)

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

### Azure DevOps Pipelines (fédération d'identité de charge de travail)

| Champ | Valeur |
|---|---|
| Émetteur | `https://vstoken.dev.azure.com/<ORGANIZATION_ID>` |
| Substitution requise | **Non** |

---

## Exemple combiné : les quatre fournisseurs

```yaml
oidc:
  allowed_issuers:
    - https://token.actions.githubusercontent.com
    - https://accounts.google.com
    - https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E
    - https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0
  trusted_jwks_hosts:
    https://accounts.google.com:
      - www.googleapis.com
```

---

## Valider votre configuration de bout en bout

```bash
# 1. Mint a token from your CI provider.
# 2. Decode the token header to confirm 'kid' is set.
echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null | jq .
# 3. Confirm 'iss' matches an entry in allowed_issuers.
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .iss
```

Modes d'échec à prévoir :

| Symptôme dans les journaux | Cause | Correction |
|---|---|---|
| `issuer "X" not in allowed list` | `iss` absent de `allowed_issuers` | Ajoutez l'URL de l'émetteur exactement comme elle apparaît dans le jeton. |
| `token header missing kid` | Le jeton n'a pas de `kid` | L'émetteur est mal configuré ; ce service rejette les jetons sans `kid`. |
| `key "X" not found in JWKS` | L'émetteur a renouvelé ses clés | Le cache JWKS a un TTL de 1 h: attendez ou redémarrez les pods. |
| `jwks_uri host "X" is not the issuer host and not in the trusted JWKS host override` | Le JWKS de l'émetteur est sur un autre hôte | Ajoutez l'hôte à `trusted_jwks_hosts`. |
| `audience mismatch (server required_audience)` | L'`aud` du jeton ne contient pas `oidc.required_audience` | Transmettez la bonne audience au workflow (`core.getIDToken('<value>')`). |
| `audience check failed` (par politique) | L'`aud` du jeton ne correspond pas au champ `audience:` de la politique | Définissez `audience:` dans `.sts.yaml` pour correspondre au workflow. |

## Maintenance : détection de la dérive des hôtes JWKS

Les fournisseurs cloud changent occasionnellement d'hôtes JWKS. Exécutez cette vérification périodiquement et alertez sur tout écart: **ne mettez pas à jour automatiquement**.

```bash
#!/usr/bin/env bash
# scripts/check-jwks-drift.sh
set -euo pipefail

VALUES="${1:-values.yaml}"

for iss in $(yq '.oidc.allowed_issuers[]' "$VALUES"); do
  iss_host=$(echo "$iss" | sed -E 's#^https?://([^/]+).*#\1#')
  observed=$(curl -fsS "${iss}/.well-known/openid-configuration" \
    | jq -r '.jwks_uri | sub("^https?://"; "") | sub("/.*$"; "")') || {
      echo "FAIL: discovery for $iss did not respond"
      continue
    }

  if [ "$observed" = "$iss_host" ]; then
    continue
  fi

  pinned=$(yq ".oidc.trusted_jwks_hosts[\"$iss\"][]" "$VALUES" 2>/dev/null || true)
  if ! grep -qx "$observed" <<< "$pinned"; then
    echo "DRIFT: $iss now publishes JWKS at $observed (not in trusted_jwks_hosts)"
  fi
done
```

Intégrez-le à un job CI hebdomadaire ; traitez toute ligne DRIFT comme un élément de revue de sécurité.
