---
title: Métriques
description: Noms, types, étiquettes des métriques Prometheus, signification opérationnelle et requêtes d'alerte recommandées.
weight: 4
translationKey: metrics
translationStatus: pending-review
---

Toutes les métriques sont exposées à `GET /metrics` au format texte Prometheus avec le préfixe `githubsts_`.

**Mise à niveau depuis une version sans pools d'Apps ?** Chaque métrique de GitHub App, de limite de débit et d'accessibilité ci-dessous porte désormais une étiquette `instance` supplémentaire ; voir [Migration : étiquette instance des métriques de pool]({{< relref "/operations/upgrades#migration--étiquette-instance-des-métriques-de-pool" >}}) pour la liste des métriques concernées, les requêtes PromQL avant/après et une liste de contrôle étape par étape.

## Authentifier les collectes

L'authentification par secret partagé Bearer est la seule méthode propre à `GET /metrics`. Définissez `GITHUBSTS_METRICS_AUTH_TOKEN` pour l'activer :

```bash
export GITHUBSTS_METRICS_AUTH_TOKEN="remplacer-par-un-secret-aléatoire"
```

Cet exemple suppose que github-sts sert HTTPS sur le port 8443 avec un certificat approuvé par l'hôte Prometheus. Consultez [TLS natif et mTLS]({{< relref "/reference/configuration" >}}) pour configurer le serveur.

Configurez la tâche de collecte Prometheus avec le même jeton. Préférez un fichier monté depuis votre gestionnaire de secrets plutôt que de stocker le jeton directement dans `prometheus.yml` :

```yaml
scrape_configs:
  - job_name: github-sts
    scheme: https
    static_configs:
      - targets: ["github-sts:8443"]
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/secrets/github-sts-metrics-token
    tls_config:
      ca_file: /etc/prometheus/certs/github-sts-ca.crt
```

Le fichier d'identifiants doit contenir uniquement la valeur du jeton. Lorsque le paramètre n'est pas vide, vérifiez qu'une requête sans jeton renvoie `401` et qu'une requête avec le jeton renvoie `200` :

```bash
curl --cacert /chemin/vers/github-sts-ca.crt -o /dev/null -s -w '%{http_code}\n' \
  https://github-sts:8443/metrics
# 401

curl --cacert /chemin/vers/github-sts-ca.crt -o /dev/null -s -w '%{http_code}\n' \
  -H "Authorization: Bearer $GITHUBSTS_METRICS_AUTH_TOKEN" \
  https://github-sts:8443/metrics
# 200
```

Lorsque le paramètre est vide, le point de terminaison reste sans authentification. HTTPS protège le jeton Bearer en transit, mais n'authentifie pas le collecteur. Le mTLS natif peut authentifier les clients pour l'ensemble du serveur, y compris `/health` et `/ready`. Un proxy inverse ou un maillage de services peut fournir d'autres méthodes d'authentification en dehors de github-sts.

## Métriques HTTP

| Métrique | Type | Description |
|---|---|---|
| `githubsts_http_requests_total` | Counter | Requêtes HTTP par méthode, chemin, statut |
| `githubsts_http_request_duration_seconds` | Histogram | Latence des requêtes HTTP |
| `githubsts_http_requests_in_flight` | Gauge | Requêtes concurrentes |

## Métriques d'échange de jeton

| Métrique | Type | Description |
|---|---|---|
| `githubsts_token_exchanges_total` | Counter | Tentatives d'échange par app, instance, scope, identity, issuer, result |
| `githubsts_token_exchange_duration_seconds` | Histogram | Latence d'échange par app, instance, scope, identity, issuer |
| `githubsts_oidc_validation_errors_total` | Counter | Échecs OIDC par issuer, reason |

## Prévention de rejeu JTI

| Métrique | Type | Description |
|---|---|---|
| `githubsts_jti_replay_attempts_total` | Counter | Tentatives de rejeu JTI détectées |
| `githubsts_jti_cache_errors_total` | Counter | Erreurs d'opération du cache JTI par error_type |

## Métriques de politique

| Métrique | Type | Description |
|---|---|---|
| `githubsts_policy_loads_total` | Counter | Chargements de politique par app, backend, result |
| `githubsts_policy_cache_hits_total` | Counter | Succès du cache par app |
| `githubsts_policy_cache_misses_total` | Counter | Échecs du cache par app |

## Métriques de l'API GitHub

| Métrique | Type | Description |
|---|---|---|
| `githubsts_github_api_calls_total` | Counter | Appels à l'API GitHub par app, instance, endpoint, result |
| `githubsts_github_tokens_issued_total` | Counter | Jetons émis par app, instance, scope, permissions |
| `githubsts_github_rate_limit_remaining` | Gauge | Limite de débit restante par app, instance, resource |
| `githubsts_github_rate_limit_limit` | Gauge | Requêtes maximales autorisées dans la fenêtre courante, par app, instance, resource |
| `githubsts_github_rate_limit_used` | Gauge | Requêtes utilisées dans la fenêtre courante, par app, instance, resource |
| `githubsts_github_rate_limit_reset_timestamp` | Gauge | Horodatage Unix du redémarrage de la fenêtre, par app, instance, resource |
| `githubsts_github_rate_limit_remaining_percent` | Gauge | Pourcentage de la limite de débit restant, par app, instance, resource |
| `githubsts_github_rate_limit_exceeded_total` | Counter | Événements de dépassement de la limite de débit primaire, par app, instance, resource, caller |
| `githubsts_github_secondary_rate_limit_total` | Counter | Événements de limite de débit secondaire (abus), par app, instance, caller |
| `githubsts_github_secondary_rate_limit_retry_after_seconds` | Gauge | Valeur retry-after actuelle en secondes, par app, instance |

Chaque instance du pool (étiquette `instance`) a sa propre série de limite de débit : une App avec 3 instances rapporte 3 séries `githubsts_github_rate_limit_remaining` indépendantes, pas une seule agrégée. Une App non poolée (une seule instance) porte quand même l'étiquette, avec `instance` égale à son unique instance normalisée.

## Accessibilité de GitHub

| Métrique | Type | Description |
|---|---|---|
| `githubsts_github_reachable` | Gauge | Accessibilité de l'API GitHub (1/0) par app, instance |
| `githubsts_github_reachability_check_duration_seconds` | Histogram | Latence des sondes d'accessibilité, par app, instance |
| `githubsts_github_reachability_failures_total` | Counter | Échecs des sondes d'accessibilité, par app, instance, reason |

## Métriques de pool d'Apps

Visibilité sur la sélection d'instance pour une App poolée (`apps.<name>.instances` ; voir [Configuration]({{< relref "/reference/configuration#pools-dapps-rotation-multi-instances-pour-la-limite-de-débit" >}})). Une App non poolée est un pool d'une instance et émet quand même ces métriques, avec `instances=1` et chaque résultat de sélection à `selected`. L'étiquette `instance` sur cette page identifie une GitHub App physique au sein d'un pool, pas un réplica du serveur github-sts.

| Métrique | Type | Description |
|---|---|---|
| `githubsts_app_pool_instances` | Gauge | Taille du pool configurée, par app |
| `githubsts_app_pool_selection_total` | Counter | Résultats de sélection, par app, instance, outcome |
| `githubsts_app_pool_exhausted_total` | Counter | Requêtes où toutes les instances du pool ont échoué, par app |

L'étiquette `outcome` de `githubsts_app_pool_selection_total` vaut aujourd'hui `selected`, `skipped_unreachable`, ou `failover`. (`skipped_rate_limited` est réservée à la stratégie `rate_limit_aware` prévue, pas encore implémentée ; voir [Configuration]({{< relref "/reference/configuration#pools-dapps-rotation-multi-instances-pour-la-limite-de-débit" >}}).)

`githubsts_app_pool_exhausted_total` est le signal à surveiller par alerte : il signifie que toutes les instances du pool de cette App ont échoué pour une requête. Qu'une seule instance voie sa limite de débit chuter ne signifie pas en soi que des requêtes échouent : le pool a déjà basculé autour d'elle.

## Métriques d'audit

| Métrique | Type | Description |
|---|---|---|
| `githubsts_audit_events_logged_total` | Counter | Événements d'audit journalisés par result |
| `githubsts_audit_log_errors_total` | Counter | Erreurs d'écriture du journal d'audit par backend |
| `githubsts_audit_events_dropped_total` | Counter | Événements d'audit abandonnés (tampon plein) |

## Autres métriques

| Métrique | Type | Description |
|---|---|---|
| `githubsts_rate_limit_rejections_total` | Counter | Requêtes rejetées par la limitation de débit par IP |
| `githubsts_ready` | Gauge | Préparation de l'instance (1/0) |

## Alertes recommandées

```promql
# Sustained OIDC validation errors — possible misconfiguration or attack
rate(githubsts_oidc_validation_errors_total[5m]) > 0

# JTI replay attempts — investigate immediately
rate(githubsts_jti_replay_attempts_total[5m]) > 0

# GitHub API unreachable — tokens will fail
githubsts_github_reachable == 0

# Audit events dropped — increase buffer or sink throughput
rate(githubsts_audit_events_dropped_total[5m]) > 0

# Exchange latency regression
histogram_quantile(0.99, rate(githubsts_token_exchange_duration_seconds_bucket[5m])) > 1

# Rate limit approaching exhaustion
githubsts_github_rate_limit_remaining_percent < 10

# Secondary rate limit active
githubsts_github_secondary_rate_limit_total > 0

# App pool exhausted: every instance failed a request
rate(githubsts_app_pool_exhausted_total[5m]) > 0
```
