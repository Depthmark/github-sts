---
title: Référence API
description: Points de terminaison HTTP, méthodes, paramètres, réponses, codes d'erreur, vérifications de santé et exemples client Go.
weight: 1
translationKey: api
translationStatus: pending-review
---

## Échange de jeton

### `GET /sts/exchange`

Échangez un jeton Bearer OIDC contre un jeton d'installation GitHub à portée limitée.

| Paramètre | Obligatoire | Description |
|---|---|---|
| `scope` | Oui | `org/repo` (niveau dépôt) ou `org` (niveau organisation) |
| `identity` | Oui | Sélecteur de politique ; correspond à `{base_path}/{app}/{identity}.sts.yaml` |
| `app` | Non | Nom de l'App (par défaut à l'App unique configurée) |

```bash
curl -H "Authorization: Bearer $OIDC_TOKEN" \
  "http://localhost:8080/sts/exchange?scope=myorg/myrepo&app=default&identity=ci"
```

### `POST /sts/exchange`

Même point de terminaison, variante avec corps JSON.

```bash
curl -X POST -H "Authorization: Bearer $OIDC_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"scope":"myorg/myrepo","app":"default","identity":"ci"}' \
  http://localhost:8080/sts/exchange
```

### Réponse

**Succès (200) :**

```json
{
  "token": "ghs_xxxxxxxxxxxxxxxxxxxx",
  "scope": "myorg/myrepo",
  "app": "default",
  "identity": "ci",
  "permissions": {
    "contents": "read",
    "pull_requests": "write"
  }
}
```

Le jeton `ghs_…` renvoyé est un jeton d'installation GitHub App standard. Il expire selon la durée de vie des jetons d'installation de GitHub (actuellement une heure).

### Réponses d'erreur

Les réponses d'erreur partagent cette forme :

```json
{ "error": "forbidden", "code": "policy_denied", "trace_id": "abc-123" }
```

`error` est délibérément générique afin que les attaquants ne puissent pas sonder le validateur. Utilisez le champ `code` (le code d'erreur lisible par machine) pour brancher dans votre logique cliente, et `trace_id` pour corréler avec les journaux serveur/audit (la ligne de journal porte la raison complète).

| Statut | `code` | Que corriger |
|---|---|---|
| `400` | `bad_request` | Paramètres de requête ou corps JSON manquants/invalides. |
| `403` | `oidc_invalid` | Jeton OIDC rejeté (manquant/expiré, signature invalide, `iss` inconnu, `kid` manquant, malformé). Rafraîchissez ou réémettez le jeton ; vérifiez `allowed_issuers`. |
| `403` | `audience_mismatch` | L'`aud` du jeton ne correspond pas à l'`audience:` de la politique. Transmettez la bonne valeur à `core.getIDToken(<audience>)` ou mettez à jour la politique. |
| `403` | `app_unknown` | `?app=` ne correspond à aucune App configurée. Vérifiez l'orthographe ou omettez-le lorsqu'une seule App est configurée. |
| `403` | `policy_not_found` | Aucun `.sts.yaml` pour ce `scope/app/identity`. Vérifiez le chemin du fichier : `{base_path}/{app}/{identity}.sts.yaml` dans le dépôt cible (ou le dépôt de politiques d'organisation). |
| `403` | `policy_denied` | La politique existe mais l'évaluation a échoué (subject, claim_pattern). Consultez la ligne de journal d'audit au `trace_id` pour l'écart précis. |
| `405` | `method_not_allowed` | Utilisez `GET` ou `POST`. |
| `409` | `replay_detected` | JTI déjà consommé ; obtenez un nouveau jeton OIDC. |
| `500` | `internal_error` | Problème côté serveur (backend de cache, mauvaise configuration de l'App). Consultez les journaux serveur au `trace_id`. |
| `502` | `upstream_error` | Échec de la récupération de politique ou de l'émission du jeton GitHub. Consultez les journaux serveur au `trace_id`. |

## Révocation de jeton

Les jetons émis par github-sts sont des jetons d'installation GitHub App standard et peuvent être révoqués directement via l'API GitHub :

```bash
curl -X DELETE https://api.github.com/installation/token \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json"
# 204 = révoqué, 401/404 = déjà expiré
```

Ou via le client Go :

```go
err := client.RevokeToken(ctx, token, "https://api.github.com")
```

Lorsque vous utilisez la `github-sts-action`, le jeton est révoqué automatiquement à la fin du job. Consultez [Utiliser la GitHub Action]({{< relref "/integrations/use-github-action" >}}) pour plus de détails.

## Santé et préparation

| Point de terminaison | Méthode | Succès | Échec |
|---|---|---|---|
| `/health` | `GET` | `200` avec l'état de vivacité, la posture de sécurité et l'état des bundles configurés | `401` lorsque l'authentification de santé est configurée et que le jeton Bearer est absent ou incorrect |
| `/ready` | `GET` | `200` `{"ready":true}` | `503` `{"ready":false}` |
| `/metrics` | `GET` | Format texte Prometheus | — |

`/health` est une sonde de vivacité. Lorsque l'authentification est désactivée
ou satisfaite, il renvoie `200` tant que le processus est en marche. Définissez
`health.auth_token` ou
`GITHUBSTS_HEALTH_AUTH_TOKEN` pour exiger un en-tête
`Authorization: Bearer <token>`. Un jeton absent ou incorrect renvoie `401`
avec `{"error":"unauthorized"}` et
`WWW-Authenticate: Bearer realm="health"`. Lorsque aucun de ces paramètres ne
fournit de jeton, `/health` reste sans authentification. `/ready` reste sans
authentification.

Après avoir démarré github-sts avec `GITHUBSTS_HEALTH_AUTH_TOKEN`, vérifiez le
comportement depuis le même hôte :

```bash
export GITHUBSTS_HEALTH_AUTH_TOKEN="remplacer-par-le-secret-configuré"

curl -o /dev/null -s -w '%{http_code}\n' http://127.0.0.1:8080/health
# 401

curl -o /dev/null -s -w '%{http_code}\n' \
  -H "Authorization: Bearer $GITHUBSTS_HEALTH_AUTH_TOKEN" \
  http://127.0.0.1:8080/health
# 200
```

Utilisez HTTPS chaque fois que le jeton Bearer transite sur un réseau.
L'exemple en boucle locale utilise HTTP uniquement pour la vérification locale.

`/ready` renvoie `200` avec `{"ready":true}` une fois que le serveur est en
service et `503` avec `{"ready":false}` tant qu'il ne l'est pas. La préparation
n'est pas conditionnée par l'accessibilité de l'API GitHub ; la sonde
d'accessibilité ne fait que mettre à jour la métrique
`githubsts_github_reachable`.

## Bibliothèque cliente Go

```go
import "github.com/depthmark/github-sts/client"

// Direct GitHub App token (requires the App private key)
provider, err := client.NewAppTokenProvider(appID, pemData, "myorg", "https://api.github.com")
if err != nil { /* handle */ }
token, err := provider.Token(ctx)

// STS token exchange (requires an OIDC token and the STS URL)
stsProvider := &client.STSTokenProvider{
    STSURL:     "https://sts.example.com",
    Identity:   "ci",
    Scope:      "myorg/myrepo",
    App:        "default",
    Audience:   "https://sts.example.com",
    SATokenPath: client.DefaultSATokenPath,
}
token, err = stsProvider.Token(ctx)

// Token revocation
err = client.RevokeToken(ctx, token, "https://api.github.com")
```

`NewAppTokenProvider(appID int64, pemData []byte, owner, apiURL string, opts ...Option)` renvoie `(*AppTokenProvider, error)` ; sa méthode `Token(ctx context.Context) (string, error)` émet un jeton. `STSTokenProvider` est une simple structure avec une méthode `Token(ctx)` (il n'y a pas de constructeur). `client.DefaultSATokenPath` vaut `/var/run/secrets/tokens/github-sts-token`.

Le client se trouve dans [`client/`](https://github.com/Depthmark/github-sts/tree/main/client) et est importable en tant que `github.com/depthmark/github-sts/client`.
