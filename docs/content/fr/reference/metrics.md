---
title: Métriques
description: Noms, types, étiquettes des métriques Prometheus, signification opérationnelle et requêtes d'alerte recommandées.
weight: 4
translationKey: metrics
translationStatus: pending-review
---

Toutes les métriques sont exposées à `GET /metrics` au format texte Prometheus avec le préfixe `githubsts_`.

## Métriques HTTP

| Métrique | Type | Description |
|---|---|---|
| `githubsts_http_requests_total` | Counter | Requêtes HTTP par méthode, chemin, statut |
| `githubsts_http_request_duration_seconds` | Histogram | Latence des requêtes HTTP |
| `githubsts_http_requests_in_flight` | Gauge | Requêtes concurrentes |

## Métriques d'échange de jeton

| Métrique | Type | Description |
|---|---|---|
| `githubsts_token_exchanges_total` | Counter | Tentatives d'échange par app, scope, identity, issuer, result |
| `githubsts_token_exchange_duration_seconds` | Histogram | Latence d'échange par app, scope, identity, issuer |
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
| `githubsts_github_api_calls_total` | Counter | Appels à l'API GitHub par app, endpoint, result |
| `githubsts_github_tokens_issued_total` | Counter | Jetons émis par app, scope, permissions |
| `githubsts_github_rate_limit_remaining` | Gauge | Limite de débit restante par app, resource |
| `githubsts_github_rate_limit_limit` | Gauge | Requêtes maximales autorisées dans la fenêtre courante |
| `githubsts_github_rate_limit_used` | Gauge | Requêtes utilisées dans la fenêtre courante |
| `githubsts_github_rate_limit_reset_timestamp` | Gauge | Horodatage Unix du redémarrage de la fenêtre |
| `githubsts_github_rate_limit_remaining_percent` | Gauge | Pourcentage de la limite de débit restant |
| `githubsts_github_rate_limit_exceeded_total` | Counter | Événements de dépassement de la limite de débit primaire |
| `githubsts_github_secondary_rate_limit_total` | Counter | Événements de limite de débit secondaire (abus) |
| `githubsts_github_secondary_rate_limit_retry_after_seconds` | Gauge | Valeur retry-after actuelle en secondes |

## Accessibilité de GitHub

| Métrique | Type | Description |
|---|---|---|
| `githubsts_github_reachable` | Gauge | Accessibilité de l'API GitHub (1/0) par app |
| `githubsts_github_reachability_check_duration_seconds` | Histogram | Latence des sondes d'accessibilité |
| `githubsts_github_reachability_failures_total` | Counter | Échecs des sondes d'accessibilité |

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
```
