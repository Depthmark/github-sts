---
title: Tracer les échanges de jetons
description: Configurer OpenTelemetry et lire les spans de requête, de politique, de bundle et de GitHub émis par github-sts.
weight: 5
translationKey: tracing-token-exchanges
---

Activez le traçage pour localiser la latence ou les erreurs de dépendances dans un échange de jeton. Le service exporte les traces avec OTLP et retourne l'identifiant de la trace active dans `X-Trace-ID` et les réponses d'erreur.

## Configurer le traçage

Envoyez les traces à un collecteur OpenTelemetry accessible depuis le service :

```yaml
tracing:
  enabled: true
  endpoint: "otel-collector.observability.svc:4317"
  protocol: grpc
  insecure: true
  sample_ratio: 1.0
  timeout: 10s
  service_name: github-sts
  environment: dev
```

`protocol` accepte `grpc` ou `http`. Conservez `sample_ratio` à `1.0` lorsqu'un collecteur applique un échantillonnage final. Un échantillonneur initial ne connaît pas le résultat final de l'échange. Il pourrait donc supprimer des refus, des requêtes lentes ou des tentatives de basculement.

Utilisez les variables d'environnement `GITHUBSTS_TRACING_*` correspondantes pour les champs scalaires lorsque la configuration provient de l'environnement. La map `headers` n'a pas de variable `GITHUBSTS_TRACING_HEADERS`. Si l'exportateur exige une authentification, injectez depuis un gestionnaire de secrets un fichier de configuration contenant `tracing.headers` plutôt que de versionner les valeurs.

## Lire une trace d'échange

Le span racine s'appelle `GET /sts/exchange` ou `POST /sts/exchange`. Pour une requête qui atteint le traitement OIDC, son attribut `sts.result` utilise le même ensemble fermé de résultats que l'événement d'audit. Les requêtes refusées plus tôt à cause de la méthode HTTP, de leur forme, de leurs champs ou de leur portée contiennent le statut HTTP sans `sts.result`. Les étapes de la requête apparaissent comme des spans de même niveau pour que leurs durées forment une chronologie lisible :

| Span | Opération |
|---|---|
| `sts.oidc.validate` | Valider le jeton porteur et sa signature |
| `sts.jti.reserve` | Réserver la clé de prévention de rejeu |
| `github.target.resolve` | Résoudre le dépôt cible vers son identité canonique immuable |
| `sts.policy.load` | Charger la politique de confiance applicable, y compris le jeton de lecture et la requête GitHub nécessaires |
| `sts.policy.validate` | Valider la structure de la politique de confiance |
| `sts.policy.evaluate` | Évaluer l'émetteur, le sujet et les sélecteurs de claims |
| `sts.policy.relationship` | Évaluer la relation immuable entre la source et la cible |
| `sts.permissions.narrow` | Appliquer la réduction de permissions demandée par l'appelant |
| `sts.bundle.evaluate` | Évaluer les bundles de politique d'organisation activés |
| `sts.token.issue` | Coordonner l'émission du jeton destiné à l'appelant |

Les opérations GitHub ajoutent des détails sous ces étapes :

```text
sts.policy.load
└── github.app_pool.attempt
    └── github.token.mint          sts.token.purpose=policy_fetch
        ├── github.installation.resolve  sts.cache.result=hit|miss|shared
        ├── github.app_jwt.get           sts.cache.result=hit|miss
        │   └── github.app_jwt.sign
        └── HTTP POST              http.response.status_code=201|422|...
```

`github.app_jwt.sign` apparaît uniquement lorsque le service effectue la signature RSA. Une lecture réussie du cache produit `github.app_jwt.get` sans span enfant de signature. Les requêtes sortantes vers GitHub, vers la découverte OIDC et vers JWKS utilisent des spans client HTTP OpenTelemetry.

## Diagnostiquer une erreur 502 pendant la lecture d'une politique

Une réponse HTTP 422 de GitHub pendant le chargement d'une politique produit ce chemin d'erreur :

```text
GET /sts/exchange                 sts.result=github_error, status=ERROR
└── sts.policy.load              error.type=policy_load_failed
    └── github.app_pool.attempt  github.app.instance=<instance tentée>
        └── github.token.mint    sts.token.purpose=policy_fetch
            └── HTTP POST        http.response.status_code=422
```

Le span de création du jeton indique `error.type=github_permissions_not_granted`. Vérifiez que l'installation de la GitHub App sélectionnée possède la permission demandée et peut accéder au dépôt de politiques.

Les refus d'autorisation comme `policy_denied` et `org_policy_denied` conservent le statut `Unset`. Leurs attributs `sts.result` et `sts.stage.result=denied` les distinguent des erreurs du service ou de ses dépendances sans augmenter artificiellement les alertes de taux d'erreur.

## Protection des données

Les spans ne contiennent jamais les jetons porteurs, les jetons d'installation GitHub, les valeurs des JWT de l'App, les clés privées, les en-têtes d'autorisation, les corps de requêtes, les ensembles bruts de claims, les identifiants de registre ou les corps de réponses externes. Les spans en erreur utilisent des valeurs `error.type` bornées plutôt que les messages d'erreur bruts. Les journaux d'audit restent la source détaillée des décisions d'autorisation.

## Vérifier la trace

1. Envoyez une requête d'échange qui atteint la validation OIDC avec le traçage activé.
2. Copiez `X-Trace-ID` depuis la réponse.
3. Ouvrez cette trace dans Tempo.
4. Confirmez que le span racine contient `sts.result` et que la chronologie contient les étapes atteintes par la requête.

Les étapes qui suivent un refus sont absentes, car le gestionnaire ne les exécute pas. Les spans enfants sont aussi absents lorsque la trace racine n'est pas échantillonnée.
