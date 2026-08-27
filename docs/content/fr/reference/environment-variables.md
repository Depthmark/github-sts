---
title: Variables d'environnement
description: Toutes les variables d'environnement prises en charge, les valeurs valides, les valeurs par défaut et les notes de sécurité.
weight: 3
translationKey: environment-variables
translationStatus: pending-review
---

Toutes les variables utilisent le préfixe `GITHUBSTS_`. Les variables par App suivent le modèle `GITHUBSTS_APP_{NAME}_{FIELD}`.

## Paramètres du serveur

| Variable | Par défaut | Description |
|---|---|---|
| `GITHUBSTS_CONFIG_PATH` | — | Chemin vers le fichier de configuration YAML |
| `GITHUBSTS_SERVER_HOST` | `0.0.0.0` | Hôte d'écoute HTTP |
| `GITHUBSTS_SERVER_PORT` | `8080` | Port d'écoute HTTP |
| `GITHUBSTS_SERVER_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `GITHUBSTS_SERVER_SUPPRESS_HEALTH_LOGS` | `true` | Supprimer les journaux d'accès des points de terminaison de santé |
| `GITHUBSTS_SERVER_SHUTDOWN_TIMEOUT` | `10s` | Délai d'arrêt gracieux |
| `GITHUBSTS_SERVER_TRUST_FORWARDED_HEADERS` | `false` | Faire confiance à `X-Forwarded-For` pour l'IP du client |
| `GITHUBSTS_SERVER_TLS_CERT_FILE` | — | Chemin vers le certificat du serveur (PEM). HTTPS est activé lorsque cette variable et `_TLS_KEY_FILE` sont définies. |
| `GITHUBSTS_SERVER_TLS_KEY_FILE` | — | Chemin vers la clé privée du serveur (PEM) |
| `GITHUBSTS_SERVER_TLS_CLIENT_CA_FILE` | — | Chemin vers le bundle de CA clientes de confiance (PEM). Lorsqu'il est défini, les certificats clients sont exigés et vérifiés (mTLS). |
| `GITHUBSTS_SERVER_TLS_MIN_VERSION` | `1.2` | Version minimale de TLS : `1.2` ou `1.3`. |
| `GITHUBSTS_SERVER_TLS_CIPHER_SUITES` | — | Liste de suites de chiffrement TLS 1.2 autorisées, séparées par des virgules (noms IANA). Vide = valeurs par défaut de Go. Ignoré lorsque `min_version` est `1.3`. |
| `GITHUBSTS_SERVER_TLS_RELOAD_INTERVAL` | `0` | Intervalle de rechargement des certificats (ex. `1h`). `0` désactive le rechargement. Nécessite que le certificat et la clé soient définis. |

## Paramètres de la GitHub App

| Variable | Par défaut | Description |
|---|---|---|
| `GITHUBSTS_APP_{NAME}_APP_ID` | *obligatoire* | ID numérique de la GitHub App |
| `GITHUBSTS_APP_{NAME}_PRIVATE_KEY` | *obligatoire* | Chaîne PEM (mutuellement exclusive avec `_PATH`) |
| `GITHUBSTS_APP_{NAME}_PRIVATE_KEY_PATH` | — | Chemin vers le fichier PEM |
| `GITHUBSTS_APP_{NAME}_ORG_POLICY_REPO` | — | Dépôt des politiques d'organisation (par ex. `.github`) |
| `GITHUBSTS_APP_{NAME}_POLICY_RESOLUTION` | `org_first` | Mode de résolution : `org_first`, `repo_first` (obsolète) ou `org_only` |
| `GITHUBSTS_APP_{NAME}_ROTATION_STRATEGY` | `round_robin` | Stratégie de sélection du pool : `round_robin` ou `rate_limit_aware` (acceptée, pas encore implémentée ; voir [Configuration]({{< relref "/reference/configuration#pools-dapps-rotation-multi-instances-pour-la-limite-de-débit" >}})) |
| `GITHUBSTS_APP_{NAME}_ROTATION_MIN_REMAINING_PCT` | `0` | `rate_limit_aware` uniquement ; actuellement sans effet |
| `GITHUBSTS_APP_{NAME}_ROTATION_MAX_ATTEMPTS` | taille du pool, plafonnée à `3` | Limite le nombre de bascules par requête |

Chaque instance d'un pool (`apps.<name>.instances[N]` en YAML) peut aussi être définie ou surchargée individuellement, en base 1 et de façon contiguë : le chargeur s'arrête au premier index `N` où aucune des quatre variables ci-dessous n'est définie.

| Variable | Par défaut | Description |
|---|---|---|
| `GITHUBSTS_APP_{NAME}_INSTANCE_{N}_APP_ID` | — | ID numérique de la GitHub App pour l'instance `N` du pool |
| `GITHUBSTS_APP_{NAME}_INSTANCE_{N}_PRIVATE_KEY` | — | Chaîne PEM pour l'instance `N` du pool (mutuellement exclusive avec `_PATH`) |
| `GITHUBSTS_APP_{NAME}_INSTANCE_{N}_PRIVATE_KEY_PATH` | — | Chemin vers le fichier PEM pour l'instance `N` du pool |
| `GITHUBSTS_APP_{NAME}_INSTANCE_{N}_NAME` | `app_id` (converti en chaîne) | Étiquette de métriques/audit pour l'instance `N` du pool |

## Paramètres de politique et de sécurité

| Variable | Par défaut | Description |
|---|---|---|
| `GITHUBSTS_POLICY_BASE_PATH` | `.github/sts` | Chemin de base dans les dépôts pour les politiques de confiance |
| `GITHUBSTS_POLICY_CACHE_TTL` | `60s` | TTL du cache de politique (`0` pour désactiver) |
| `GITHUBSTS_OIDC_ALLOWED_ISSUERS` | — | Liste d'autorisation d'émetteurs séparée par des virgules. Obligatoire ; une liste vide est une erreur de validation. |
| `GITHUBSTS_OIDC_REQUIRED_AUDIENCE` | — | Revendication `aud` obligatoire au niveau du serveur. Lorsqu'elle est définie, chaque jeton doit porter cette valeur (défense en profondeur en plus du champ `audience:` par politique). |
| `GITHUBSTS_JTI_BACKEND` | `memory` | `memory` ou `redis` |
| `GITHUBSTS_JTI_REDIS_URL` | — | URL de connexion Redis (lorsque backend=`redis`) |
| `GITHUBSTS_JTI_TTL` | `1h` | Fenêtre de protection contre le rejeu JTI |

## Paramètres d'audit

| Variable | Par défaut | Description |
|---|---|---|
| `GITHUBSTS_AUDIT_FILE_ENABLED` | `true` | Activer la journalisation d'audit par fichier |
| `GITHUBSTS_AUDIT_FILE_PATH` | `/var/log/github-sts/audit.json` | Chemin du fichier de journal d'audit |
| `GITHUBSTS_AUDIT_BUFFER_SIZE` | `1024` | Taille du tampon du canal d'audit |

## Paramètres des métriques

| Variable | Par défaut | Description |
|---|---|---|
| `GITHUBSTS_METRICS_ENABLED` | `true` | Activer les métriques Prometheus |
| `GITHUBSTS_METRICS_AUTH_TOKEN` | — | Jeton Bearer pour le point de terminaison `/metrics` (vide = non authentifié) |
| `GITHUBSTS_METRICS_RATE_LIMIT_POLL_ENABLED` | `true` | Interroger `GET /rate_limit` périodiquement |
| `GITHUBSTS_METRICS_RATE_LIMIT_POLL_INTERVAL` | `60s` | Intervalle d'interrogation de la limite de débit |
| `GITHUBSTS_METRICS_REACHABILITY_PROBE_ENABLED` | `true` | Sonder l'accessibilité de l'API GitHub |
| `GITHUBSTS_METRICS_REACHABILITY_PROBE_INTERVAL` | `30s` | Intervalle de la sonde d'accessibilité |

## Paramètres de limitation de débit

| Variable | Par défaut | Description |
|---|---|---|
| `GITHUBSTS_RATE_LIMIT_ENABLED` | `false` | Activer la limitation de débit par IP sur `/sts/exchange` |
| `GITHUBSTS_RATE_LIMIT_RATE` | `10` | Requêtes par seconde par IP |
| `GITHUBSTS_RATE_LIMIT_BURST` | `20` | Taille maximale de rafale par IP |
| `GITHUBSTS_RATE_LIMIT_EXEMPT_CIDRS` | — | Plages CIDR exemptées de la limitation de débit |

## Notes de sécurité

- **Clés privées :** Préférez `GITHUBSTS_APP_{NAME}_PRIVATE_KEY_PATH` à `_PRIVATE_KEY`. Les variables d'environnement apparaissent dans les listes de processus et les points de terminaison de débogage. Montez les clés comme fichiers depuis un magasin de secrets.
- **Audience :** Définissez `GITHUBSTS_OIDC_REQUIRED_AUDIENCE` en production. C'est une défense en profondeur en plus du champ `audience:` par politique.
- **Backend JTI :** Utilisez `redis` pour les déploiements multi-réplicas. Le backend `memory` est par instance et n'empêche pas le rejeu inter-réplicas.
- **Liste d'autorisation d'émetteurs :** `GITHUBSTS_OIDC_ALLOWED_ISSUERS` est obligatoire. Une liste vide est une erreur de validation, pas un repli « accepter n'importe quel émetteur ».
- **TLS :** Le TLS natif est optionnel et ne s'active que lorsque `GITHUBSTS_SERVER_TLS_CERT_FILE` et `GITHUBSTS_SERVER_TLS_KEY_FILE` sont toutes deux définies. Sur Kubernetes, préférez la terminaison TLS à l'ingress/Gateway ; utilisez le TLS natif pour les déploiements autonomes ou lors du re-chiffrement du trafic Gateway→backend. Définir `GITHUBSTS_SERVER_TLS_CLIENT_CA_FILE` active le mTLS et exige que chaque client présente un certificat signé par cette CA.
- **Suites de chiffrement :** `GITHUBSTS_SERVER_TLS_CIPHER_SUITES` accepte les noms IANA (ex. `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`). Seules les suites non-insécures de `tls.CipherSuites()` de Go sont valides. Les noms inconnus ou non sécurisés sont une erreur de validation. Lorsque `min_version` est `1.3`, définir des suites de chiffrement est également une erreur de validation.
- **Rechargement des certificats :** `GITHUBSTS_SERVER_TLS_RELOAD_INTERVAL` active un sondage périodique des fichiers de certificat et de clé. Lorsque les fichiers changent, ils sont rechargés sans redémarrer le processus. Sans cette option, la rotation des certificats nécessite un redémarrage du processus.
