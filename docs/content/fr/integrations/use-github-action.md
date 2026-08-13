---
title: Utiliser la GitHub Action
description: "Comment intégrer github-sts-action dans vos workflows : prérequis, permissions OIDC, audience explicite, entrées, gestion du jeton de sortie."
weight: 2
translationKey: use-github-action
translationStatus: pending-review
---

L'action [github-sts-action](https://github.com/Depthmark/github-sts-action) simplifie l'échange de jeton OIDC dans les workflows GitHub Actions.

## Prérequis

- Une instance github-sts en cours d'exécution (voir [Déployer avec Helm]({{< relref "/integrations/deploy-with-helm" >}}))
- Une politique de confiance définie pour l'identité de votre workflow
- La permission `id-token: write` sur le job

## Utilisation rapide

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: Depthmark/github-sts-action@v0.1.0
        id: sts
        with:
          sts-url: https://sts.example.com
          audience: https://sts.example.com
          scope: ${{ github.repository }}
          identity: ci
      - name: Use the token
        run: |
          git clone https://x-access-token:${{ steps.sts.outputs.token }}@github.com/${{ github.repository }}.git
```

## Entrées

| Entrée | Obligatoire | Description |
|---|---|---|
| `sts-url` | Oui | URL de base de l'instance github-sts |
| `audience` | Oui | Audience OIDC (doit correspondre au champ `audience:` de la politique de confiance) |
| `scope` | Oui | `org/repo` (niveau dépôt) ou `org` (niveau organisation) |
| `identity` | Oui | Sélecteur de politique (correspond à `{base_path}/{app}/{identity}.sts.yaml`) |
| `app` | Non | Nom de l'App (par défaut à celui du serveur) |
| `extra-params` | Non | Paramètres de requête supplémentaires ajoutés à l'URL d'échange |

## Sorties

| Sortie | Description |
|---|---|
| `token` | Le jeton d'installation GitHub à portée limitée |
| `scope` | Écho de la portée demandée |
| `app` | Nom de l'App utilisée |
| `identity` | Identité utilisée |
| `permissions` | Permissions accordées (JSON) |
| `expires_at` | Horodatage d'expiration du jeton |

## Exigences de sécurité

1. **Épinglez l'action à un tag de version spécifique ou à un SHA de commit complet.** N'utilisez jamais `@main` en production.
2. **Définissez toujours une `audience` explicite.** Elle doit correspondre à l'`audience:` de votre politique de confiance.
3. **Utilisez `subject` (correspondance exacte) dans les politiques de confiance** dès que possible, pas `subject_pattern`.
4. **Accordez le minimum de permissions.** L'action n'a besoin que de `id-token: write`.

## Exemple de workflow complet

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
      deployments: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - uses: Depthmark/github-sts-action@v0.1.0
        id: sts
        with:
          sts-url: https://sts.example.com
          audience: https://sts.example.com
          scope: ${{ github.repository }}
          identity: deploy

      - name: Deploy
        uses: some/deploy-action@v1
        with:
          token: ${{ steps.sts.outputs.token }}
```

## Référence de l'action

Pour la référence complète des entrées/sorties, consultez le [README de github-sts-action](https://github.com/Depthmark/github-sts-action).

> Épinglez toujours un tag de version ou un SHA de commit spécifique. N'utilisez pas `@main` ni un tag flottant dans les workflows de production.

## Suivant

- [De bout en bout sur Kubernetes]({{< relref "/integrations/end-to-end-github-actions-on-kubernetes" >}}): procédure complète
- [Compatibilité]({{< relref "/integrations/compatibility" >}}): combinaisons de composants vérifiées
- [Politiques de confiance]({{< relref "/learn/trust-policies" >}}): concepts et exemples de politique
