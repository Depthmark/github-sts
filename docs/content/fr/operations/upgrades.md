---
title: Mises à niveau
description: Politique de compatibilité, processus de publication, guide de migration et guide de déploiement de la migration immutable-subject.
weight: 5
translationKey: upgrades
translationStatus: pending-review
---

## Politique de compatibilité

github-sts suit la [version sémantique](https://semver.org). Tant que le projet est en pré-1.0 :

- **Minor (`0.X.0`)**: nouvelles fonctionnalités et peut contenir des changements cassants ; lisez les notes de version avant la mise à niveau.
- **Patch (`0.0.X`)**: corrections de bugs et améliorations non cassantes.

Les changements cassants sont signalés en haut des notes de chaque version sur GitHub.

| Composant | Compatibilité |
|---|---|
| Client Go (`client/`) | Même majeure/mineure que le serveur ; les montées de version mineure peuvent ajouter des méthodes mais n'en supprimeront pas avant la 1.0. |
| Schéma de politique de confiance | Ajouts rétrocompatibles uniquement. Les nouveaux champs obligatoires (par ex. `audience`) sont introduits derrière une fenêtre d'obsolescence: voir les notes de version. |
| Configuration (YAML / env) | Ajouts rétrocompatibles uniquement. Les champs supprimés/renommés émettent un avertissement au démarrage pendant une version mineure avant suppression. |
| API HTTP (`/sts/exchange`) | Forme requête/réponse stable. De nouveaux paramètres optionnels et `code`s d'erreur peuvent être ajoutés ; les existants ne changent pas de sens. |

## Processus de publication

1. Les notes de version sont générées automatiquement par [release-please](https://github.com/googleapis/release-please) à partir des Conventional Commits.
2. Les changements cassants sont signalés manuellement dans la description de la version.
3. Les images Docker sont construites et signées avec la signature keyless cosign.
4. Le chart Helm est mis à jour dans une version coordonnée.

Consultez les [versions](https://github.com/Depthmark/github-sts/releases) pour l'historique complet.

## Migration : champ `audience`

Le champ `audience` est obligatoire dans chaque politique de confiance. Une politique sans lui est rejetée à l'analyse.

**Avant :**

```yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:org/repo:ref:refs/heads/main
permissions:
  contents: read
```

**Après :**

```yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:org/repo:ref:refs/heads/main
audience: https://sts.example.com
permissions:
  contents: read
```

**Migration étape par étape :**

1. Choisissez une valeur d'audience unique à votre déploiement STS (par ex. `https://sts.example.com`).
2. Ajoutez `audience:` à chaque politique de confiance.
3. Mettez à jour chaque appel `core.getIDToken()` des workflows pour utiliser l'audience choisie.
4. (Optionnel) Définissez `GITHUBSTS_OIDC_REQUIRED_AUDIENCE` comme défense en profondeur.
5. Déployez la version mise à jour de github-sts.
6. Vérifiez que les échanges réussissent ; surveillez les erreurs `audience_mismatch` dans les métriques et journaux.

## `immutable_subject` n'est pas un champ pris en charge

Le champ `immutable_subject` ne fait pas partie du schéma de politique actuel. Les clés inconnues sont ignorées par l'analyseur YAML, donc une politique contenant `immutable_subject` est acceptée mais le champ n'a aucun effet. Utilisez `subject` pour une correspondance exacte ou `subject_pattern` pour une regex.

**Avant :**

```yaml
issuer: https://token.actions.githubusercontent.com
immutable_subject: repo:myorg/myrepo:ref:refs/heads/main
permissions:
  contents: read
```

**Après :**

```yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:myorg/myrepo:ref:refs/heads/main
audience: https://sts.example.com
permissions:
  contents: read
```

## Liste de contrôle avant mise à niveau

1. Lisez les notes de version pour les changements cassants.
2. Consultez la matrice [Compatibilité]({{< relref "/integrations/compatibility" >}}) pour les combinaisons de composants vérifiées.
3. Testez dans un environnement de pré-production.
4. Mettez à jour les politiques de confiance si des changements de schéma sont requis.
5. Déployez avec une stratégie canary ou blue-green.
6. Surveillez `githubsts_oidc_validation_errors_total` et `githubsts_token_exchanges_total` pour les régressions.
