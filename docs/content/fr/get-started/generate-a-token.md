---
title: Générer un jeton
description: Écrivez une politique de confiance et échangez un jeton OIDC contre un jeton d'installation GitHub limité.
weight: 4
translationKey: get-started-generate-a-token
translationStatus: pending-review
---

Une fois l'App configurée et installée, il reste deux éléments : une **politique de confiance**
(qui peut demander, et pour quoi) et le **jeton OIDC** qu'une identité présente pour prouver qui elle est.

## Écrire une politique de confiance

Les politiques de confiance résident **dans le dépôt cible** à `.github/sts/{app}/{identity}.sts.yaml`.
Pour `app=default` et `identity=ci` dans `myorg/myrepo`, c'est :

```
myorg/myrepo/.github/sts/default/ci.sts.yaml
```

Exemple minimal pour un workflow GitHub Actions sur `main` :

```yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:myorg/myrepo:ref:refs/heads/main
audience: https://sts.example.com
permissions:
  contents: read
  pull_requests: write
```

> **`audience` est obligatoire**, et doit correspondre à l'audience que la charge de travail demande
> dans son jeton OIDC. C'est ce qui lie un jeton à *ce* déploiement github-sts et à aucun autre.
> Voir [Émetteurs OIDC](../../oidc-issuers/) pour savoir comment les jetons de chaque fournisseur
> sont validés. Préférez `subject` exact à `subject_pattern` : un motif correspond à plus
> d'identités que celle que vous avez testée.

## Demander le jeton OIDC

Depuis un workflow GitHub Actions, demandez un jeton OIDC avec une audience explicite :

```yaml
jobs:
  deploy:
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
```

Limitez `id-token: write` au job qui en a besoin, pas à tout le workflow.

## L'échanger

```bash
curl -H "Authorization: Bearer $OIDC_TOKEN" \
  "https://sts.example.com/sts/exchange?scope=myorg/myrepo&app=default&identity=ci"
```

```json
{
  "token": "ghs_xxxxxxxxxxxxxxxxxxxx",
  "expires_in": 3600,
  "scope": "myorg/myrepo",
  "app": "default",
  "identity": "ci",
  "permissions": {
    "contents": "read",
    "pull_requests": "write"
  }
}
```

Le jeton `ghs_…` est un jeton d'installation GitHub App standard, limité exactement aux dépôts et
permissions déclarés par la politique. `expires_in` indique le nombre de secondes qu'il lui reste,
ce qui permet à un job de longue durée de le renouveler à temps au lieu de supposer une durée de
vie. Voir [la référence API]({{< relref "/reference/api" >}}) pour les cas où le champ est absent.
Pour un wrapper prêt à l'emploi autour de cet échange dans
Actions, voir [le démarrage rapide de la GitHub Action]({{< relref "/integrations/github-action/quickstart" >}}). Le `curl` manuel
ci-dessus fonctionne depuis n'importe quel système CI capable de produire un jeton OIDC.

## Liste de vérification sécurité

- [ ] `id-token: write` est limité au job spécifique, pas à tout le workflow
- [ ] L'audience est explicite et correspond à la politique de confiance
- [ ] La politique de confiance utilise `subject` (correspondance exacte) autant que possible, pas `subject_pattern`
- [ ] Les permissions de la politique de confiance sont le minimum requis
- [ ] L'URL de github-sts utilise HTTPS en production

## Suite

[Surveiller l'utilisation](../../integrations/monitor-usage/) : consultez les métriques et le journal d'audit pour confirmer ce qui a été émis.
