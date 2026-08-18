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

En production, déployez github-sts avec le chart Helm plutôt que de gérer ce fichier à la main. Consultez [Déployer avec Helm]({{< relref "/integrations/deploy-with-helm" >}}).

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
