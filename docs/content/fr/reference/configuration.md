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

En production, déployez github-sts avec le chart Helm plutôt que de gérer ce fichier à la main. Consultez [Installation du chart Helm]({{< relref "/integrations/helm-chart/installation" >}}).

## Pools d'Apps (rotation multi-instances pour la limite de débit)

Un nom d'App logique (`apps.<name>`) peut être adossé à une seule GitHub App (`app_id` / `private_key` / `private_key_path`, comme ci-dessus) ou à un pool de plusieurs GitHub Apps physiques sous `instances:`. Chaque instance possède ses propres identifiants de GitHub App, donc son propre quota de limite de débit primaire GitHub indépendant : le plafond effectif d'une App poolée sur le trafic `/sts/exchange` augmente avec le nombre d'instances. (Cette « instance » est une GitHub App physique, sans rapport avec un réplica du serveur github-sts ; voir [Architecture]({{< relref "/concepts/architecture#pools-dapps-et-basculement" >}}).) Les appelants ne voient jamais que le nom d'App logique dans `?app=` ; quelle instance a servi une requête donnée reste interne, et n'apparaît que dans l'étiquette `instance` des métriques et dans le journal d'audit (voir [Métriques]({{< relref "/reference/metrics#métriques-de-pool-dapps" >}})).

```yaml
apps:
  checkout:
    org_policy_repo: ".github"
    instances:
      - name: checkout-1          # optionnel ; par défaut app_id si omis
        app_id: 111111
        private_key_path: "/etc/github-sts/keys/checkout-1.pem"
      - name: checkout-2
        app_id: 222222
        private_key_path: "/etc/github-sts/keys/checkout-2.pem"
      - name: checkout-3
        app_id: 333333
        private_key_path: "/etc/github-sts/keys/checkout-3.pem"
    rotation:
      strategy: round_robin        # round_robin (défaut) | rate_limit_aware
      min_remaining_pct: 5         # rate_limit_aware uniquement
      max_attempts: 3              # limite le nombre de bascules par requête
```

Par défaut, github-sts fait tourner les instances d'un pool en round-robin (un curseur par requête, pour que les tentatives d'une même requête parcourent des membres consécutifs plutôt que de retirer au hasard), écarte toute instance actuellement signalée comme inaccessible par la sonde d'accessibilité, et bascule vers l'instance suivante lorsque celle tentée renvoie une erreur réessayable. Réessayable signifie une erreur réseau/timeout, une réponse 5xx, ou un 403 portant un signal de limite de débit (`Retry-After` ou `X-RateLimit-Remaining: 0`) ; un 422 (les autorisations ou dépôts demandés dépassent ce que cette installation accorde) ou tout autre 4xx n'est pas réessayé, car un identifiant différent ne peut pas corriger une incohérence d'autorisations. `rotation.max_attempts` limite le nombre d'instances tentées par requête (par défaut : taille du pool, plafonnée à 3).

Règles :

- `instances` et les champs plats `app_id` / `private_key` / `private_key_path` sont mutuellement exclusifs sur une App. Une App en forme plate est traitée comme un pool d'une instance.
- `rotation` n'a de sens que sur une App poolée (`instances` défini) : le définir sur une App en forme plate est une erreur de validation, car cela serait autrement du YAML sans aucun effet.
- Chaque instance nécessite `app_id` et exactement un des deux champs `private_key` / `private_key_path`.
- `app_id` doit être unique **au sein** du pool d'une App. Le même `app_id` réutilisé entre les pools de deux Apps logiques différentes est autorisé (elles partagent déjà un quota de limite de débit par construction) mais journalise un avertissement au démarrage, car c'est plus souvent un copier-coller erroné qu'une configuration intentionnelle.
- `name` est optionnel et vaut par défaut `app_id` (converti en chaîne). Comme il devient une valeur d'étiquette Prometheus, il est limité à 100 caractères parmi `[a-zA-Z0-9._/-]`.
- `rotation.strategy` vaut `round_robin` (défaut) ou `rate_limit_aware`. **`rate_limit_aware` est accepté aujourd'hui mais pas encore implémenté** : un pool ainsi configuré se comporte exactement comme `round_robin`, et github-sts journalise un avertissement au démarrage à ce sujet. Cette valeur est réservée à une stratégie de contournement proactif qui classera les instances selon leur pourcentage de limite de débit restant observé en dernier, plutôt que de seulement réagir à un échec en direct.
- `rotation.min_remaining_pct` (plage `[0, 100)`) ne s'applique qu'à `rate_limit_aware` et n'a actuellement aucun effet pour la raison ci-dessus.
- `rotation.max_attempts` vaut par défaut `min(len(instances), 3)` lorsqu'il est omis ou à `0`.

**Exigence opérationnelle :** chaque instance d'un pool doit être installée avec des autorisations et un accès aux dépôts identiques. github-sts traite les membres du pool comme interchangeables ; il ne vérifie pas actuellement qu'ils le sont réellement, donc une instance mal configurée ne se manifeste que par un 422 intermittent ou un échec d'accessibilité, sur la fraction des requêtes qui tombent dessus.

## TLS natif et mTLS

github-sts peut servir HTTPS directement, mais ne gère pas le cycle de vie des certificats. Le TLS est **activé implicitement** lorsque vous fournissez à la fois un certificat et une clé ; fournissez un bundle de CA clientes pour exiger et vérifier les certificats clients (mTLS) :

```yaml
server:
  port: 8443
  tls:
    cert_file: /etc/github-sts/tls/tls.crt
    key_file: /etc/github-sts/tls/tls.key
    # Optionnel : activer le mTLS en faisant confiance à un bundle de CA clientes.
    # client_ca_file: /etc/github-sts/tls/client-ca.crt

    # Optionnel : imposer TLS 1.3 uniquement (par défaut : "1.2" — TLS 1.2 et supérieur).
    # min_version: "1.3"

    # Optionnel : restreindre aux suites de chiffrement TLS 1.2 spécifiées (noms IANA).
    # Omettez pour utiliser les valeurs par défaut de Go. Ne peut pas être défini avec min_version "1.3".
    # cipher_suites:
    #   - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    #   - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    #   - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256

    # Optionnel : sonder les fichiers cert/clé à intervalle régulier et les recharger
    # lorsqu'ils changent, permettant une rotation des certificats sans interruption.
    # "0" désactive le sondage (par défaut). Sans cela, la rotation nécessite un redémarrage.
    # reload_interval: 1h
```

Règles :

- `cert_file` et `key_file` doivent être définies ensemble. Définir l'une sans l'autre est une erreur de validation.
- `client_ca_file` requiert `cert_file` et `key_file`.
- `min_version` accepte `"1.2"` (par défaut) ou `"1.3"`.
- `cipher_suites` accepte des noms IANA. Seules les suites non-insécures de la bibliothèque standard de Go sont valides. Définir des suites de chiffrement avec `min_version: "1.3"` est également une erreur de validation.
- `reload_interval` active un sondage périodique des fichiers de certificat et de clé. Lorsque les fichiers changent, ils sont rechargés sans redémarrer le processus. Requiert `cert_file` et `key_file`.
- La vérification des clients utilise `RequireAndVerifyClientCert` lorsque `client_ca_file` est défini.

Le modèle de déploiement recommandé consiste à terminer le TLS au niveau de l'ingress/Gateway de la plateforme lorsqu'il est disponible, et à utiliser le TLS natif pour les déploiements autonomes ou lors du re-chiffrement du trafic Gateway→backend (par ex. `BackendTLSPolicy` de Gateway API). Consultez [Modèle de sécurité]({{< relref "/concepts/security-model" >}}) pour les recommandations sur les frontières de confiance.

## Politiques de confiance

Les politiques de confiance sont des fichiers YAML stockés **dans le dépôt cible** qui définissent quelles identités OIDC peuvent demander des jetons et avec quelles autorisations.

**Emplacement :** `.github/sts/{app_name}/{identity}.sts.yaml`

Le chemin de base est configurable via `GITHUBSTS_POLICY_BASE_PATH` (par défaut `.github/sts`).

Consultez le guide [Politiques de confiance]({{< relref "/concepts/trust-policies" >}}) pour le schéma complet de politique, les exemples et les conseils de sécurité.
