---
title: De bout en bout GitHub Actions sur Kubernetes
description: "Procédure complète prise en charge : installer le chart Helm, configurer github-sts, créer une politique de confiance, utiliser l'Action, échanger un jeton et vérifier."
weight: 3
translationKey: end-to-end-github-actions-on-kubernetes
translationStatus: pending-review
---

Ce guide présente un déploiement complet : installation Helm, création de politique de confiance, intégration de la GitHub Action, échange de jeton et vérification.

## Vue d'ensemble

Vous allez :

1. Installer github-sts sur Kubernetes via Helm
2. Configurer une politique de confiance pour votre workflow
3. Exécuter un workflow qui utilise github-sts-action
4. Échanger un jeton OIDC contre un jeton d'installation GitHub à portée limitée
5. Vérifier les journaux d'audit et les métriques

## 1. Installer github-sts

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

Vérifiez :

```bash
kubectl get pods -n github-sts
kubectl logs -n github-sts deploy/github-sts
```

## 2. Créer une politique de confiance

Dans votre dépôt cible, créez `.github/sts/default/ci.sts.yaml` :

```yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:myorg/myrepo:ref:refs/heads/main
audience: https://sts.example.com
permissions:
  contents: read
  pull_requests: write
```

Validez et poussez.

## 3. Configurer le workflow

Créez `.github/workflows/deploy.yml` :

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

      - uses: Depthmark/github-sts-action@v0.2.0
        id: sts
        with:
          sts-url: https://sts.example.com
          audience: https://sts.example.com
          scope: ${{ github.repository }}
          identity: ci

      - name: Verify the exchange
        run: |
          # token est enregistré comme secret : il s'affiche *** dans le journal.
          # Tester qu'il est non vide fonctionne malgré tout.
          test -n "${{ steps.sts.outputs.token }}" && echo "Token received"

      - name: Use the token
        run: |
          gh repo view ${{ github.repository }} --json name
        env:
          GH_TOKEN: ${{ steps.sts.outputs.token }}
```

## 4. Exécuter le workflow

Poussez sur la branche `main`. Le workflow va :

1. Demander un jeton OIDC avec l'audience `https://sts.example.com`
2. L'envoyer au point de terminaison `/sts/exchange` de github-sts
3. Recevoir un jeton d'installation à portée limitée
4. L'utiliser pour accéder au dépôt

## 5. Vérifier

### Vérifier la sortie de l'action

L'action renvoie la portée, l'App, l'identité et les permissions du jeton.

### Vérifier les journaux d'audit du serveur

```bash
kubectl logs -n github-sts deploy/github-sts | grep "result.success"
```

Champs attendus :
- `result: success`
- `issuer: https://token.actions.githubusercontent.com`
- `subject: repo:myorg/myrepo:ref:refs/heads/main`

### Vérifier les métriques

```bash
# Échange réussi
curl -s https://sts.example.com/metrics | grep githubsts_token_exchanges_total{result=\"success\"}

# Jeton émis
curl -s https://sts.example.com/metrics | grep githubsts_github_tokens_issued_total

# Aucune erreur
curl -s https://sts.example.com/metrics | grep githubsts_oidc_validation_errors_total
```

### Vérifier la révocation du jeton

Les jetons expirent automatiquement après une heure. Vous pouvez aussi les révoquer manuellement :

```yaml
- name: Revoke token at job end
  if: always()
  run: |
    curl -X DELETE https://api.github.com/installation/token \
      -H "Authorization: Bearer ${{ steps.sts.outputs.token }}"
```

## Scénarios d'échec à tester

### 1. Audience manquante

Supprimez `audience:` de la politique de confiance. La politique ne peut pas être analysée et l'échange renvoie `502` avec `upstream_error`.

### 2. Mauvaise audience

Gardez `audience:` dans la politique mais demandez une audience différente dans le workflow. L'échange renvoie `403` avec `audience_mismatch`.

### 3. Mauvaise branche

Modifiez le workflow pour qu'il se déclenche sur une branche autre que `main`. L'échange doit échouer avec `policy_denied` car `subject` ne correspond pas.

### 4. Mauvaise identité

Changez `identity: ci` en `identity: unknown`. L'échange doit échouer avec `policy_not_found`.

## Dépannage

Consultez [Dépannage]({{< relref "/operations/troubleshooting" >}}) pour le guide de diagnostic complet.

## Suivant

- [Compatibilité]({{< relref "/integrations/compatibility" >}}): combinaisons de composants vérifiées
- [Entrées et sorties de l'action]({{< relref "/integrations/github-action/reference" >}}) : chaque entrée et sortie, avec valeurs par défaut et règles de validation
- [Référence des valeurs]({{< relref "/integrations/helm-chart/values" >}}) : chaque valeur du chart, avec ses valeurs par défaut
