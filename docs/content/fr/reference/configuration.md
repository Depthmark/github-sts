---
title: Configuration
description: Structure de configuration YAML, valeurs par défaut et référence complète.
weight: 2
translationKey: configuration
translationStatus: pending-review
---

github-sts se configure via un fichier YAML, des variables d'environnement, ou les deux. Les variables d'environnement remplacent les valeurs du YAML, ce qui fait du YAML la source de vérité pour les valeurs par défaut et des variables d'environnement le bon endroit pour les secrets et les surcharges par environnement.

## Configuration YAML

Pointez github-sts vers un fichier de configuration avec `GITHUBSTS_CONFIG_PATH` :

```bash
export GITHUBSTS_CONFIG_PATH=/etc/github-sts/config.yaml
```

Consultez [`config/github-sts.example.yaml`](https://github.com/Depthmark/github-sts/blob/main/config/github-sts.example.yaml) dans le dépôt pour un exemple complet.

Une configuration minimale :

```yaml
server:
  port: 8080
  log_level: info

oidc:
  allowed_issuers:
    - https://token.actions.githubusercontent.com
  required_audience: https://sts.example.com

apps:
  default:
    app_id: 123456
    private_key_path: /etc/github-sts/keys/default.pem
    org_policy_repo: .github
    policy_resolution: org_first
```

Les niveaux de journal valides sont en minuscules : `debug | info | warn | error`. `oidc.allowed_issuers` doit contenir au moins un émetteur ; une liste vide est une erreur de validation.

En production, déployez github-sts avec le chart Helm plutôt que de gérer ce fichier à la main. Consultez [Déployer avec Helm]({{< relref "/integrations/deploy-with-helm" >}}).

## Politiques de confiance

Les politiques de confiance sont des fichiers YAML stockés **dans le dépôt cible** qui définissent quelles identités OIDC peuvent demander des jetons et avec quelles autorisations.

**Emplacement :** `.github/sts/{app_name}/{identity}.sts.yaml`

Le chemin de base est configurable via `GITHUBSTS_POLICY_BASE_PATH` (par défaut `.github/sts`).

Consultez le guide [Politiques de confiance]({{< relref "/learn/trust-policies" >}}) pour le schéma complet de politique, les exemples et les conseils de sécurité.
