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

## Migration : étiquette `instance` des métriques de pool

La mise à niveau vers une version avec les [pools d'Apps]({{< relref "/reference/configuration#pools-dapps-rotation-multi-instances-pour-la-limite-de-débit" >}}) ajoute une étiquette `instance` à chaque métrique de GitHub App, de limite de débit et d'accessibilité qui existait déjà. Cela s'applique à chaque déploiement, pas seulement à ceux qui configurent `instances:` : une App à instance unique est normalisée en interne comme un pool d'une instance, donc elle porte quand même l'étiquette (voir [Métriques]({{< relref "/reference/metrics" >}})) :

```text
githubsts_token_exchanges_total
githubsts_token_exchange_duration_seconds
githubsts_github_api_calls_total
githubsts_github_tokens_issued_total
githubsts_github_rate_limit_limit
githubsts_github_rate_limit_remaining
githubsts_github_rate_limit_used
githubsts_github_rate_limit_reset_timestamp
githubsts_github_rate_limit_remaining_percent
githubsts_github_rate_limit_exceeded_total
githubsts_github_secondary_rate_limit_total
githubsts_github_secondary_rate_limit_retry_after_seconds
githubsts_github_reachable
githubsts_github_reachability_check_duration_seconds
githubsts_github_reachability_failures_total
```

**Si chaque App reste à instance unique,** le nombre de séries est inchangé : chacune des métriques ci-dessus a toujours exactement une série par App (par resource, par endpoint, etc.), avec simplement une étiquette de plus. Une requête qui n'exige pas un ensemble d'étiquettes exact continue de renvoyer le même résultat. La plupart des tableaux de bord et alertes n'ont pas besoin d'être modifiés.

**Si une App adopte un pool de N instances,** le nombre de séries de cette App pour chaque métrique ci-dessus est multiplié par N : une série par instance, pas une série agrégée. Un panneau ou une alerte écrit avant l'existence de l'étiquette affichera désormais, ou déclenchera une alerte sur, N séries distinctes au lieu d'une.

**Avant** (instance unique, ou avant la mise à niveau) :

```promql
githubsts_github_rate_limit_remaining_percent{github_app="checkout"} < 10
```

**Après** (agrégation sur le nombre d'instances de l'App, quel qu'il soit, pour que la requête conserve son ancienne signification quelle que soit la taille du pool) :

```promql
min(githubsts_github_rate_limit_remaining_percent{github_app="checkout"}) by (github_app) < 10
```

Ou, pour alerter sur un identifiant précis plutôt que sur toute l'App logique (nouvelle capacité, non obligatoire) :

```promql
githubsts_github_rate_limit_remaining_percent{github_app="checkout", github_app_instance="checkout-2"} < 10
```

**Migration étape par étape :**

1. Avant la mise à niveau, dressez la liste des panneaux de tableau de bord et des règles d'alerte référençant l'une des métriques ci-dessus.
2. Pour chacun, décidez s'il doit continuer à rapporter une valeur par App (l'envelopper dans `sum`/`min`/`max` `by (...)` en excluant `instance` du regroupement) ou commencer à rapporter le détail par instance (ajouter `instance` à la clause `by (...)` à la place).
3. Mettez à jour ces requêtes avant ou immédiatement après la mise à niveau ; le changement d'étiquette prend effet dès que la nouvelle version commence à servir du trafic.
4. Déployez.
5. Vérifiez que les panneaux affichent le nombre de séries attendu et que les alertes se déclenchent toujours dans les conditions attendues.

## Migration : renommage des étiquettes de métriques pour éviter les collisions Kubernetes

**Cette version renomme trois étiquettes sur toutes les métriques `githubsts_`. Chaque requête de tableau de bord et chaque règle d'alerte qui les sélectionne doit être mise à jour.**

| Ancienne étiquette | Nouvelle étiquette | Motif du changement |
|---|---|---|
| `app` | `github_app` | Étiquette de charge de travail Kubernetes, et étiquette de flux Loki |
| `instance` | `github_app_instance` | Cible de scrape Prometheus (`ip-du-pod:port`) |
| `endpoint` | `api_endpoint` | ServiceMonitor de Prometheus Operator : nom du port de service scrapé |

Une collision de ce type ne lève jamais d'erreur. Le scrape l'emporte silencieusement, et la valeur propre à l'application est soit renommée en `exported_*`, soit purement perdue. La panne ne se manifeste que par un panneau qui ne renvoie aucune ligne.

C'était déjà le cas. Une variable de tableau de bord « GitHub App Instance » fondée sur `exported_instance` restait définitivement vide, car cette étiquette n'existait sur aucune série : le scrape avait pris `instance` et la valeur du membre du pool n'y avait pas survécu. Sous les anciens noms, **aucune étiquette par instance n'était interrogeable sur les métriques.** Après ce renommage, `github_app_instance` existe et fonctionne.

**Avant :**

```promql
githubsts_github_rate_limit_remaining_percent{app="checkout", instance="checkout-2"} < 10
sum(rate(githubsts_github_tokens_issued_total[5m])) by (app)
githubsts_github_api_calls_total{endpoint="create_token"}
```

**Après :**

```promql
githubsts_github_rate_limit_remaining_percent{github_app="checkout", github_app_instance="checkout-2"} < 10
sum(rate(githubsts_github_tokens_issued_total[5m])) by (github_app)
githubsts_github_api_calls_total{api_endpoint="create_token"}
```

**Migration pas à pas :**

1. Recherchez `githubsts_` dans les tableaux de bord et les règles d'alerte, et listez chaque requête qui sélectionne ou regroupe sur `app`, `instance` ou `endpoint`.
2. Réécrivez-les avec les nouveaux noms. Toute requête qui utilisait auparavant `exported_app` ou `exported_instance` doit désormais utiliser simplement `github_app` / `github_app_instance` : le préfixe `exported_` n'existait qu'à cause de la collision et disparaît avec elle.
3. Déployez, puis vérifiez que les panneaux renvoient des lignes. Un panneau silencieusement vide est précisément le mode de défaillance que ce renommage corrige : vérifiez plutôt que de supposer.
4. La continuité des séries ne survit pas à un renommage d'étiquette : les anciennes séries s'arrêtent et de nouvelles commencent. Les requêtes de plage couvrant la mise à niveau montreront une rupture.

Un test de garde (`internal/metrics/labels_test.go`) fait désormais échouer la compilation si une métrique déclare `app`, `instance`, `job`, `endpoint`, `service`, `namespace`, `pod`, `container` ou `node` : cette classe de collision ne peut plus réapparaître.

## Liste de contrôle avant mise à niveau

1. Lisez les notes de version pour les changements cassants.
2. Consultez la matrice [Compatibilité]({{< relref "/integrations/compatibility" >}}) pour les combinaisons de composants vérifiées.
3. Testez dans un environnement de pré-production.
4. Mettez à jour les politiques de confiance si des changements de schéma sont requis.
5. Déployez avec une stratégie canary ou blue-green.
6. Surveillez `githubsts_oidc_validation_errors_total` et `githubsts_token_exchanges_total` pour les régressions.
