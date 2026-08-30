---
title: Sécurité
description: Versions prises en charge, processus de signalement des vulnérabilités et politique de divulgation responsable.
weight: 3
translationKey: security
translationStatus: pending-review
---

## Versions prises en charge

| Version | Statut |
|---|---|
| `v0.0.x` (dernière) | Prise en charge |
| `v0.0.3` | Prise en charge |

Nous prenons en charge la dernière version et la version précédente. Les versions plus anciennes ne reçoivent pas de correctifs de sécurité.

## Signaler une vulnérabilité

**N'ouvrez pas d'issue publique.** Signalez plutôt les vulnérabilités en privé :

1. Utilisez le [signalement privé de vulnérabilité](https://github.com/Depthmark/github-sts/security/advisories/new) de GitHub (recommandé)
2. Ou écrivez à [oss-security@adelisle.com](mailto:oss-security@adelisle.com) en indiquant `github-sts` dans l'objet

Incluez :

- Une description de la vulnérabilité
- Les étapes pour la reproduire
- Les versions concernées
- Toute correction suggérée

## Délai de réponse

1. **Accusé de réception :** Sous 48 heures
2. **Évaluation :** Sous 5 jours ouvrés
3. **Correction et divulgation :** Coordonnées avec le signalant

Nous suivons un processus de divulgation coordonnée. Nous vous demandons de ne pas divulguer publiquement la vulnérabilité tant que nous n'avons pas publié un correctif et que les utilisateurs n'ont pas eu le temps de mettre à niveau.

## Score de sécurité de la chaîne d'approvisionnement

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Depthmark/github-sts/badge)](https://scorecard.dev/viewer/?uri=github.com/Depthmark/github-sts)

[OpenSSF Scorecard](https://github.com/ossf/scorecard) évalue les pratiques de sécurité de la chaîne d'approvisionnement du dépôt après l'arrivée de modifications sur `main` et selon une planification hebdomadaire. Les résultats publics deviennent disponibles dans le [visualiseur Scorecard](https://scorecard.dev/viewer/?uri=github.com/Depthmark/github-sts) après la première analyse réussie. Les mainteneurs disposant d'un accès en écriture au dépôt peuvent examiner les constats exploitables sous forme d'alertes d'analyse du code dans l'[onglet Sécurité](https://github.com/Depthmark/github-sts/security/code-scanning).

Les contrôles Scorecard sont des heuristiques automatisées, et non une certification de sécurité. Examinez chaque contrôle et ses conseils de correction au lieu de vous fier uniquement au score global.

## Modèle de sécurité

Pour le modèle de sécurité complet, consultez [Modèle de sécurité]({{< relref "/concepts/security-model" >}}).

## Remerciements

Nous remercions les chercheurs suivants pour la divulgation responsable de vulnérabilités :

*Aucun pour l'instant: soyez le premier.*
