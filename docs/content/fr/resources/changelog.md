---
title: Journal des modifications
description: Historique des versions et compatibilité des versions pour github-sts.
weight: 1
translationKey: changelog
translationStatus: pending-review
---

Le journal des modifications faisant autorité se trouve dans le dépôt à [`CHANGELOG.md`](https://github.com/Depthmark/github-sts/blob/main/CHANGELOG.md) et est généré automatiquement par [release-please](https://github.com/googleapis/release-please) à partir des Conventional Commits.

- **Versions :** <https://github.com/Depthmark/github-sts/releases>
- **Comparer les versions :** <https://github.com/Depthmark/github-sts/compare>

## Versionnage

github-sts suit la [version sémantique](https://semver.org). Tant que le projet est en pré-1.0 :

- **Minor (`0.X.0`)**: nouvelles fonctionnalités et peut contenir des changements cassants ; lisez les notes de version avant la mise à niveau.
- **Patch (`0.0.X`)**: corrections de bugs et améliorations non cassantes.

Les changements cassants sont signalés en haut des notes de chaque version sur GitHub.

## Compatibilité

| Composant | Compatibilité |
|---|---|
| Client Go (`client/`) | Même majeure/mineure que le serveur ; les montées de version mineure peuvent ajouter des méthodes mais n'en supprimeront pas avant la 1.0. |
| Schéma de politique de confiance | Ajouts rétrocompatibles uniquement. Les nouveaux champs obligatoires (par ex. `audience`) sont introduits derrière une fenêtre d'obsolescence: voir les notes de version. |
| Configuration (YAML / env) | Ajouts rétrocompatibles uniquement. Les champs supprimés/renommés émettent un avertissement au démarrage pendant une version mineure avant suppression. |
| API HTTP (`/sts/exchange`) | Forme requête/réponse stable. De nouveaux paramètres optionnels et `code`s d'erreur peuvent être ajoutés ; les existants ne changent pas de sens. |
