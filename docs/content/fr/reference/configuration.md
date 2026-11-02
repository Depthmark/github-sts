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

Par défaut, github-sts fait tourner les instances d'un pool en round-robin, écarte toute instance actuellement signalée comme inaccessible par la sonde d'accessibilité, et bascule vers l'instance suivante lorsque celle tentée renvoie une erreur réessayable. La rotation avance d'un cran par échange de jeton : c'est l'émission finale du jeton de l'échange qui la fait avancer, et la résolution de la cible et les lectures de politique qui la précèdent commencent sur le membre que cette émission utilisera. Un échange reste donc sur un seul membre, et les émissions se répartissent également dans le pool, quelle que soit sa taille. Les tentatives d'une même requête parcourent des membres consécutifs. Réessayable signifie une erreur réseau/timeout, une réponse 5xx, ou un 403 portant un signal de limite de débit (`Retry-After` ou `X-RateLimit-Remaining: 0`) ; un 422 (les autorisations ou dépôts demandés dépassent ce que cette installation accorde) ou tout autre 4xx n'est pas réessayé, car un identifiant différent ne peut pas corriger une incohérence d'autorisations. `rotation.max_attempts` limite le nombre d'instances tentées par requête (par défaut : taille du pool, plafonnée à 3).

Règles :

- `instances` et les champs plats `app_id` / `private_key` / `private_key_path` / `signer` sont mutuellement exclusifs sur une App. Une App en forme plate est traitée comme un pool d'une instance.
- `rotation` n'a de sens que sur une App poolée (`instances` défini) : le définir sur une App en forme plate est une erreur de validation, car cela serait autrement du YAML sans aucun effet.
- Chaque instance nécessite `app_id` et exactement un des champs `private_key` / `private_key_path` / `signer` (voir [Garder la clé de l'App dans un coffre de clés](#signer)).
- `app_id` doit être unique **au sein** du pool d'une App. Le même `app_id` réutilisé entre les pools de deux Apps logiques différentes est autorisé (elles partagent déjà un quota de limite de débit par construction) mais journalise un avertissement au démarrage, car c'est plus souvent un copier-coller erroné qu'une configuration intentionnelle.
- `name` est optionnel et vaut par défaut `app_id` (converti en chaîne). Comme il devient une valeur d'étiquette Prometheus, il est limité à 100 caractères parmi `[a-zA-Z0-9._/-]`.
- `rotation.strategy` vaut `round_robin` (défaut) ou `rate_limit_aware`. Avec `rate_limit_aware`, chaque requête place en fin d'ordre tout membre dont l'installation pour l'organisation demandée est connue comme étant sous `rotation.min_remaining_pct`, ou sans requête restante, dans une fenêtre de limite de débit pas encore réinitialisée. Le membre n'est pas retiré : il est encore tenté quand tous les autres membres échouent. Chaque fois qu'une requête le passe sans le tenter, `githubsts_app_pool_selection_total{outcome="skipped_rate_limited"}` le compte. Quand tous les membres sont bas, ou que rien n'est connu, l'ordre est un simple round-robin.
- Les relevés de quota de `rate_limit_aware` proviennent uniquement de réponses qui ont consommé une requête : les appels de github-sts faits avec ses propres jetons d'installation et le sondeur de limite de débit. Ils peuvent être en retard sur un épuisement rapide, borné par `metrics.rate_limit_poll_force_counted_interval`, faute de quoi la sonde conditionnelle du sondeur deviendrait non fiable pendant toute la durée de vie en cache d'un jeton (~55 minutes), et un compteur dépensé uniquement par des jetons clients n'est jamais visible : la bascule réactive reste le filet de sécurité. Voir la [référence des métriques]({{< relref "/reference/metrics" >}}) pour l'origine des relevés. github-sts journalise un avertissement au démarrage quand `rate_limit_aware` est défini alors que `metrics.rate_limit_poll_enabled` est désactivé.
- `rotation.min_remaining_pct` (plage `[0, 100)`) ne s'applique qu'à `rate_limit_aware`. Avec `0`, seul un membre sans requête restante est placé en fin d'ordre.
- `rotation.max_attempts` vaut par défaut `min(len(instances), 3)` lorsqu'il est omis ou à `0`.

**Exigence opérationnelle :** chaque instance d'un pool doit être installée avec des autorisations et un accès aux dépôts identiques. github-sts traite les membres du pool comme interchangeables ; il ne vérifie pas actuellement qu'ils le sont réellement, donc une instance mal configurée ne se manifeste que par un 422 intermittent ou un échec d'accessibilité, sur la fraction des requêtes qui tombent dessus.

## Garder la clé de l'App dans un coffre de clés {#signer}

Gardez la clé privée de l'App hors de github-sts : désignez une clé détenue par Azure Key Vault, ou Managed HSM, au lieu d'un PEM. github-sts envoie au coffre un condensé SHA-256 et reçoit la signature du JWT de l'App : la clé n'entre jamais dans le processus. Chaque clé signe sous une identité cloud que vous définissez une seule fois dans `cloud_identities` et que son `signer` désigne par son nom.

```yaml
cloud_identities:
  vault-one:
    azure:
      client_id: 00000000-0000-0000-0000-000000000001
      tenant_id: 00000000-0000-0000-0000-000000000003
  vault-two:
    azure:
      client_id: 00000000-0000-0000-0000-000000000002
      tenant_id: 00000000-0000-0000-0000-000000000003

apps:
  checkout:
    app_id: 111111
    signer:
      cloud_identity: vault-one
      key_id: https://vault-one.vault.azure.net/keys/checkout
  settings:
    instances:
      - app_id: 222222
        signer:
          cloud_identity: vault-two
          key_id: https://vault-two.vault.azure.net/keys/settings
```

Règles :

- `private_key`, `private_key_path` et `signer` sont mutuellement exclusifs, et chaque instance en exige exactement un. Le même bloc `signer` se place sur une App à plat ou sur une instance de pool.
- Un broker utilise une seule sorte de source de clé : chaque instance a un `signer`, ou chaque instance a un PEM. Un mélange arrête le broker au démarrage, et rien ne bascule d'une sorte à l'autre.
- `signer.cloud_identity` désigne une entrée de `cloud_identities`, et le cloud de cette identité choisit le fournisseur. Un nom qui n'est pas défini, ou une identité qu'aucun `signer` ne désigne, arrête le broker au démarrage.
- `key_id` est l'identifiant de la clé tel qu'Azure l'affiche, `https://<vault>.vault.azure.net/keys/<name>`, éventuellement suivi de `/<version>`. Sans version, github-sts signe avec la version courante de la clé : importer une nouvelle version dans le coffre effectue donc la rotation de la clé sans changer la configuration.
- github-sts signe un premier JWT d'App au démarrage et refuse de démarrer si une clé ne peut pas signer : il signale ainsi un identifiant erroné, un rôle manquant, un coffre injoignable, un coffre hors du locataire de son identité ou une identité qui ne fait pas confiance au jeton du pod avant de recevoir du trafic.
- Après le démarrage, github-sts demande au coffre une signature par instance d'App toutes les 9 minutes, partagée par les échanges et les sondeurs en arrière-plan. Une panne du coffre arrête les échanges dès que le JWT d'App en cache expire ; un pool bascule vers une instance dont la clé signe encore.

**Identités cloud.** Chaque entrée de `cloud_identities` est une identité managée affectée par l'utilisateur. `azure.client_id` et `azure.tenant_id` sont tous deux obligatoires, et ce sont des GUID : l'ID client et l'ID de locataire qu'affiche la ressource Azure de l'identité. Chaque clé désigne son identité : github-sts n'a donc pas d'identité par défaut et ignore `AZURE_CLIENT_ID` et `AZURE_TENANT_ID`. Le coffre d'une clé doit se trouver dans le `tenant_id` de son identité : Key Vault demande un jeton dans le locataire du coffre, et github-sts ne demande de jetons que dans celui de l'identité, si bien qu'un coffre d'un autre locataire arrête le broker au démarrage avec une erreur qui le dit. Pour un coffre d'un autre locataire, utilisez une identité créée dans ce locataire. `cloud_identities` se définit uniquement en YAML ; un `signer` peut aussi se définir par [variables d'environnement]({{< relref "/reference/environment-variables#github-app-settings" >}}).

**S'authentifier auprès d'Azure.** github-sts s'authentifie par identité de charge de travail et rien d'autre, si bien qu'aucun secret Azure n'existe : il échange le jeton projeté du compte de service Kubernetes du pod contre chaque identité. Il lit le chemin du jeton dans `AZURE_FEDERATED_TOKEN_FILE` et refuse de démarrer si cette variable est absente. Le chart Helm de github-sts projette le jeton et définit la variable ; le webhook Azure d'identité de charge de travail fait de même pour un pod étiqueté `azure.workload.identity/use: "true"`. Pour chaque identité, Azure a besoin de :

1. Un crédentiel fédéré avec l'émetteur des comptes de service du cluster, le sujet `system:serviceaccount:<namespace>:<service account>` et l'audience `api://AzureADTokenExchange`. Plusieurs identités peuvent faire confiance au même compte de service : Microsoft Entra ID échange l'unique jeton contre l'identité que désigne chaque clé.
2. La permission `sign` sur ses propres clés et rien d'autre : un rôle personnalisé qui ne contient que `Microsoft.KeyVault/vaults/keys/sign/action`, attribué sur chaque clé.
3. Un pare-feu de coffre qui admet l'adresse depuis laquelle le broker l'appelle.

Microsoft Entra ID doit pouvoir lire l'émetteur du cluster ; un broker sur un cluster qui ne peut pas le publier garde des PEM. Des identités distinctes séparent les octrois et les journaux d'audit par coffre, mais elles n'isolent pas les Apps au sein d'un même broker : le pod peut signer sous toute identité qui fait confiance à son compte de service. Pour isoler les Apps les unes des autres, exécutez des brokers distincts avec des comptes de service distincts.

**Importer la clé.** Importez une fois dans le coffre le PEM que GitHub a généré, puis supprimez-le. Limitez les opérations de la clé à `sign`, pour qu'aucun rôle ne puisse l'utiliser à autre chose :

```bash
az keyvault key import --vault-name vault-one --name checkout \
  --pem-file github-app.pem --ops sign
rm github-app.pem
```

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
