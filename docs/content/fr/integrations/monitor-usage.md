---
title: Surveiller l'utilisation
description: Surveillez les métriques Prometheus et lisez le journal d'audit structuré pour confirmer ce que github-sts a réellement émis.
weight: 5
translationKey: monitor-usage
translationStatus: pending-review
---

Une politique de confiance déclare ce qui est *autorisé*. Les métriques et le journal d'audit
montrent ce qui s'est réellement passé. L'écart entre les deux est là où vous repérerez une
politique mal configurée ou une identité compromise.

## Métriques Prometheus

Chaque échange est comptabilisé sur `GET /metrics`. Les deux à surveiller en premier :

```promql
# Tentatives d'échange par app, scope, identity, issuer, result
githubsts_token_exchanges_total

# Tentatives de rejeu JTI : à examiner immédiatement, cela signifie qu'un jeton a été réutilisé
rate(githubsts_jti_replay_attempts_total[5m]) > 0
```

Voir [Métriques](../../reference/metrics/) pour la liste complète : métriques HTTP, d'échange, JTI,
de politique, d'API GitHub et d'accessibilité, ainsi que les requêtes d'alerte recommandées.

## Journal d'audit

Chaque échange de jeton produit une entrée de journal d'audit structurée :

| Champ | Signification |
|---|---|
| `trace_id` | Relie un code d'erreur de réponse à la raison côté serveur |
| `issuer`, `subject` | Les revendications du jeton OIDC présenté |
| `scope`, `app`, `identity` | Les paramètres d'échange demandés |
| `jti` | L'identifiant JWT du jeton |
| `result` | `success`, `policy_denied`, `oidc_invalid`, etc. |
| `error_reason` | Pourquoi un échange refusé a été refusé |
| `duration_ms` | Latence de l'échange |

Filtrez sur `result!=success` pour repérer les tentatives refusées ou invalides ; un pic indique soit
un workflow cassé, soit quelqu'un qui teste vos politiques.

## Suite

Vous avez couvert l'ensemble du démarrage rapide. À partir d'ici :

- [Émetteurs OIDC](../../oidc-issuers/) : configurer des fournisseurs d'identité supplémentaires
- [Recettes de politiques](../../concepts/policy-recipes/) : modèles de politiques de confiance à copier-coller
- [Chart Helm]({{< relref "/integrations/helm-chart" >}}) : exécuter github-sts sur Kubernetes pour des charges de travail réelles
- [Kubernetes](../../operations/kubernetes/) : sondes, montage de secrets, TLS et comportement multi-réplicas
