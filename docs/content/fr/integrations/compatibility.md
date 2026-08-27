---
title: Compatibilité
description: "Combinaisons prises en charge des versions de github-sts, du chart Helm et de l'Action : fenêtres d'obsolescence, incompatibilités connues et dernier résultat de test de bout en bout vérifié."
weight: 4
translationKey: compatibility
translationStatus: pending-review
---

Cette page documente les combinaisons vérifiées des versions de github-sts, github-sts-helm et github-sts-action.

## Combinaisons vérifiées

| github-sts | github-sts-helm | github-sts-action | Test de bout en bout | Statut |
|---|---|---|---|---|
| `v0.0.3` | `v0.1.0` | `v0.2.0` | En attente | **Pris en charge** |

Les lignes marquées **Pris en charge** ont passé le test d'intégration de bout en bout : installation Helm, évaluation de politique de confiance, échange de jeton et vérification de fin de job.

Les lignes marquées **En attente** sont censées fonctionner sur la base de la compatibilité d'API mais n'ont pas été testées ensemble lors de la dernière exécution de test.

## Compatibilité des composants

### github-sts ↔ github-sts-helm

La version du chart Helm suit un tag d'image github-sts compatible. Vérifiez le champ `appVersion` du chart dans `Chart.yaml`.

### github-sts ↔ github-sts-action

L'Action utilise l'API stable `/sts/exchange`. Les montées de version mineure peuvent ajouter des paramètres optionnels ; les paramètres existants et les formes de réponse restent stables.

## Incompatibilités connues

| Problème | Résolution |
|---|---|
| Champ `audience` obligatoire | Chaque politique de confiance doit déclarer `audience` ; ajoutez-le et transmettez la même valeur à `core.getIDToken()` |
| `immutable_subject` non pris en charge | Le champ ne fait pas partie du schéma et est ignoré s'il est présent ; utilisez `subject` ou `subject_pattern` |
| `repositories` non appliqué | Le champ est présent mais non appliqué dans le flux d'échange ; utilisez `subject` pour restreindre à un dépôt |
| Les politiques centralisées sont mono-dépôt | Une politique d'organisation centralisée limite le jeton au seul dépôt dérivé du sujet OIDC |
| L'authentification de santé casse les sondes du chart | Le chart appelle `/health` sans jeton Bearer ; laissez `health.auth_token` vide sur les déploiements gérés par le chart |

### Authentification de santé et chart Helm

Le chart `github-sts-helm` actuel ne prend pas encore en charge
l'authentification de `/health`. Sa sonde HTTP de vivacité et son hook de test
appellent `/health` sans jeton Bearer. Activer l'authentification de santé
provoque donc des réponses `401`, un échec de la sonde de vivacité et un échec
du hook de test. Ne définissez pas `health.auth_token` ni
`GITHUBSTS_HEALTH_AUTH_TOKEN` sur un déploiement géré par le chart tant qu'une
version compatible du chart n'injecte pas le jeton depuis un Secret Kubernetes,
ne bascule pas la sonde de vivacité en TCP et ne met pas à jour le hook de test.
Les déploiements dotés d'un câblage personnalisé équivalent peuvent activer
l'authentification de santé dès maintenant.

## Politique d'obsolescence

- Les nouveaux champs obligatoires reçoivent une fenêtre d'obsolescence d'une version mineure.
- Les champs supprimés/renommés émettent un avertissement au démarrage pendant une version mineure avant suppression.
- Les changements critiques pour la sécurité (par ex. `audience` obligatoire) peuvent avoir une fenêtre plus courte, annoncée dans les notes de version.

## Test d'intégration

Le test d'intégration inter-dépôts effectue :

1. Installer le chart Helm publié sur un cluster de test
2. Démarrer une instance github-sts configurée
3. Exécuter un workflow utilisant la GitHub Action publiée
4. Vérifier l'échange de jeton réussi
5. Vérifier l'échec d'autorisation de politique (mauvaise audience)
6. Vérifier le rejet de non-correspondance d'audience
7. Vérifier la révocation du jeton en fin de job

Les résultats sont publiés dans les dépôts [github-sts-helm](https://github.com/Depthmark/github-sts-helm) et [github-sts-action](https://github.com/Depthmark/github-sts-action).

## Liens de l'écosystème

- **Chart Helm github-sts :** <https://github.com/Depthmark/github-sts-helm>
- **Documentation de l'Action github-sts :** [GitHub Action]({{< relref "/integrations/github-action" >}}) (publiée dans ce site depuis le dépôt de l'action)
- **Marketplace de l'Action github-sts :** <https://github.com/marketplace/actions/github-sts>
