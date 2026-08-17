---
title: Recettes de politiques
description: Modèles de politiques de confiance à copier-coller pour la correspondance exacte de dépôt, les restrictions de workflow, les politiques inter-dépôts et d'organisation.
weight: 4
translationKey: policy-recipes
translationStatus: pending-review
---

Modèles de politiques de confiance prêts à l'emploi pour les scénarios courants. Remplacez les valeurs d'exemple par les vôtres.

## Dépôt exact, branche exacte

Le plus sûr : un seul workflow depuis une branche spécifique.

```yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:myorg/myrepo:ref:refs/heads/main
audience: https://sts.example.com
permissions:
  contents: read
  issues: write
```

## Restriction par workflow

Restreindre à un fichier de workflow spécifique, quelle que soit la branche.

```yaml
issuer: https://token.actions.githubusercontent.com
subject_pattern: "repo:myorg/myrepo:.*"
audience: https://sts.example.com
claim_pattern:
  job_workflow_ref: "myorg/myrepo/.github/workflows/deploy\\.yml@.*"
permissions:
  deployments: write
  statuses: write
```

## Politique d'organisation (centralisée)

Placée dans `myorg/.github/.github/sts/default/release-bot.sts.yaml`, cette politique permet aux workflows du dépôt `release` d'obtenir un accès en écriture. Une politique centralisée est limitée au seul dépôt dérivé de la revendication OIDC `sub`, et non à l'organisation entière.

```yaml
issuer: https://token.actions.githubusercontent.com
subject_pattern: "repo:myorg/release:.*"
audience: https://sts.example.com
permissions:
  contents: write
  pull_requests: write
```

## Identité de charge de travail Azure

Pour les charges de travail Azure utilisant Entra ID.

```yaml
issuer: https://login.microsoftonline.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/v2.0
subject_pattern: "[a-f0-9-]+"
audience: https://sts.example.com
claim_pattern:
  azp: "your-azure-app-client-id"
permissions:
  contents: read
```

## Identité de charge de travail GCP

Pour les comptes de service GCP.

```yaml
issuer: https://accounts.google.com
subject: https://accounts.google.com/service-account-name
audience: https://sts.example.com
permissions:
  contents: read
  packages: read
```

## Restriction par environnement

Uniquement les jetons provenant d'un environnement GitHub spécifique.

```yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:myorg/myrepo:environment:production
audience: https://sts.example.com
claim_pattern:
  repository_owner: "^myorg$"
permissions:
  deployments: write
  contents: read
```

## Workflows de pull request (lecture seule)

Modèle sûr pour les workflows de PR qui nécessitent un accès en lecture.

```yaml
issuer: https://token.actions.githubusercontent.com
subject_pattern: "repo:myorg/myrepo:ref:refs/pull/.*"
audience: https://sts.example.com
permissions:
  contents: read
  pull_requests: read
  metadata: read
```

## Restreindre à un sujet sans référence fixe

Le champ `immutable_subject` ne fait pas partie du schéma actuel ; les clés inconnues sont ignorées par l'analyseur YAML. Pour restreindre une politique à une seule branche, placez la valeur exacte dans `subject`. Pour faire correspondre une plage, utilisez `subject_pattern`.

**Exact :**

```yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:myorg/myrepo:ref:refs/heads/main
audience: https://sts.example.com
permissions:
  contents: read
```

**Regex :**

```yaml
issuer: https://token.actions.githubusercontent.com
subject_pattern: "repo:myorg/myrepo:.*"
audience: https://sts.example.com
permissions:
  contents: read
```

> **Remarque :** Le champ `audience` est obligatoire. Ajoutez-le à toute politique écrite pour une version antérieure.
