---
title: Intégration GitHub Actions
description: Intégration GitHub Actions sécurisée complète utilisant OIDC id-token, liaison d'audience explicite, une politique de confiance et un échange de jeton.
weight: 2
translationKey: github-actions
translationStatus: pending-review
---

Ce guide présente une intégration GitHub Actions complète et sécurisée avec github-sts.

## Vue d'ensemble

Un workflow GitHub Actions peut s'authentifier auprès de github-sts via OIDC et recevoir un jeton d'installation à portée limitée: sans secrets, sans PAT. Le workflow :

1. Demande un jeton OIDC avec `id-token: write`
2. Transmet une audience explicite à `core.getIDToken()`
3. Envoie le jeton au point de terminaison `/sts/exchange` de github-sts
4. Reçoit un jeton d'installation GitHub à portée limitée

## Prérequis

- Une instance github-sts en cours d'exécution (voir [Démarrage rapide]({{< relref "/learn/getting-started" >}}))
- Une GitHub App installée sur votre organisation ou vos dépôts cibles
- Une politique de confiance définie dans le dépôt cible

## Étape 1 : Accorder les permissions OIDC

Ajoutez `id-token: write` à votre workflow ou à votre job :

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

## Étape 2 : Demander un jeton OIDC

Utilisez l'action `actions/github-script` ou `github-sts-action` pour obtenir un jeton OIDC avec une audience explicite :

```yaml
- name: Obtain OIDC token
  uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c379ccdee # v7.0.1
  id: oidc
  with:
    script: |
      const token = await core.getIDToken('https://sts.example.com')
      core.setOutput('token', token)
```

> **L'audience est obligatoire.** La valeur transmise à `core.getIDToken()` doit correspondre au champ `audience:` de votre politique de confiance. Consultez [Politiques de confiance]({{< relref "/learn/trust-policies" >}}) pour plus de détails.

## Étape 3 : Échanger le jeton

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

## Étape 4 : Définir la politique de confiance

Créez `.github/sts/default/ci.sts.yaml` dans votre dépôt cible :

```yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:myorg/myrepo:ref:refs/heads/main
audience: https://sts.example.com
permissions:
  contents: read
  pull_requests: write
```

## Exemple de workflow complet

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

## Utiliser github-sts-action

Pour une intégration plus simple, utilisez [github-sts-action](https://github.com/Depthmark/github-sts-action) :

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

Consultez [Utiliser la GitHub Action]({{< relref "/integrations/use-github-action" >}}) pour la référence complète.

## Liste de contrôle de sécurité

- [ ] `id-token: write` est limité au job concerné, pas à l'ensemble du workflow
- [ ] L'audience est explicite et correspond à la politique de confiance
- [ ] La politique de confiance utilise `subject` (correspondance exacte) dès que possible, pas `subject_pattern`
- [ ] Les permissions de la politique de confiance sont le minimum requis
- [ ] L'URL du STS utilise HTTPS en production
