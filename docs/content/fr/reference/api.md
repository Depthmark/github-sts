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
| `permission` | Non | Paire `nom:niveau`, répétable, restreignant le jeton en deçà de ce que la politique de confiance autorise. Omettez-la pour recevoir tout ce que la politique accorde. |

```bash
curl -H "Authorization: Bearer $OIDC_TOKEN" \
  "http://localhost:8080/sts/exchange?scope=myorg/myrepo&app=default&identity=ci"
```

### `POST /sts/exchange`

Même point de terminaison, variante avec corps JSON. L'objet `permissions` est la forme « corps de requête » du paramètre `permission`.

```bash
curl -X POST -H "Authorization: Bearer $OIDC_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"scope":"myorg/myrepo","app":"default","identity":"ci"}' \
  http://localhost:8080/sts/exchange
```

### Demander moins de privilèges {#requesting-less-privilege}

La politique de confiance est un plafond, pas une attribution figée. Un appelant peut demander un sous-ensemble des permissions de la politique, ou un niveau inférieur à celui qu'elle autorise, et recevoir un jeton limité à cela exactement. Une même politique peut ainsi servir une tâche en lecture seule et une tâche qui écrit, sans imposer ni une seconde politique ni un jeton surprivilégié.

```bash
# la politique accorde contents:write et issues:write.
# cette tâche ne fait que lire : elle ne demande que cela.
curl -X POST -H "Authorization: Bearer $OIDC_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"scope":"myorg/myrepo","app":"default","identity":"ci","permissions":{"contents":"read"}}' \
  http://localhost:8080/sts/exchange

# la même requête en GET
curl -H "Authorization: Bearer $OIDC_TOKEN" \
  "http://localhost:8080/sts/exchange?scope=myorg/myrepo&app=default&identity=ci&permission=contents:read"
```

Cette restriction ne peut que réduire les privilèges : elle ne nécessite donc aucune activation dans la politique de confiance. Chaque entrée doit déjà être accordée par la politique, au même niveau ou à un niveau supérieur. Toute autre demande constitue une tentative d'élévation et renvoie `400 bad_request` avant qu'aucun jeton ne soit émis :

| La politique accorde | Requête | Résultat |
|---|---|---|
| `contents: write` | `contents: read` | Le jeton porte `contents: read` |
| `contents: write` | `contents: write` | Le jeton porte `contents: write` |
| `contents: write`, `issues: write` | `contents: read` | Le jeton porte uniquement `contents: read` ; `issues` est retiré |
| `contents: write` | `packages: write` | `400` -- non accordé par la politique |
| `contents: write` | `contents: admin` | `400` -- au-dessus du plafond de la politique |
| `contents: write` | `{}` (objet vide) | `400` -- omettez plutôt le champ |

Omettre entièrement le champ conserve le comportement précédent : le jeton reçoit tout ce que la politique accorde.

Le corps d'erreur reste volontairement générique et ne nomme aucune permission : un appelant qui ne peut pas lire la politique de confiance ne peut donc pas la reconstituer en sondant le point de terminaison. Les opérateurs obtiennent la raison complète dans le journal d'audit via `trace_id`.

### Réponse

**Succès (200) :**

```json
{
  "token": "ghs_xxxxxxxxxxxxxxxxxxxx",
  "expires_in": 3600,
  "scope": "myorg/myrepo",
  "app": "default",
  "identity": "ci",
  "permissions": {
    "contents": "read",
    "pull_requests": "write",
    "metadata": "read"
  }
}
```

Le jeton `ghs_…` renvoyé est un jeton d'installation GitHub App standard.

`expires_in` est la durée de vie restante du jeton, en secondes entières. C'est le champ que
l'échange de jeton OAuth 2.0 (RFC 8693) définit à cet usage. Le serveur le calcule à partir de
l'expiration renvoyée par GitHub avec le jeton et le mesure au moment où il écrit la réponse :
lisez-le plutôt que de coder en dur la durée de vie actuelle d'une heure appliquée par GitHub.
Renouvelez le jeton avant que la valeur n'atteigne zéro, car il cesse alors de fonctionner.

Le champ est absent lorsque GitHub n'a renvoyé aucune expiration exploitable. Le jeton reste
valide : repliez-vous sur votre propre intervalle de renouvellement au lieu de traiter cette
absence comme une erreur.

`permissions` rapporte l'attribution que GitHub a réellement associée au jeton, relue depuis la réponse de création de jeton de GitHub. Ce n'est ni le plafond de la politique de confiance, ni la requête. Ce champ peut légitimement différer des deux : GitHub ajoute `metadata: read` à tout jeton d'installation, et une requête restreinte rapporte l'ensemble restreint. Pour savoir ce qu'une identité a le droit de demander, consultez sa politique de confiance plutôt que ce champ.

### Réponses d'erreur {#error-responses}

Les réponses d'erreur partagent cette forme :

```json
{ "error": "forbidden", "code": "policy_denied", "trace_id": "abc-123" }
```

`error` est délibérément générique afin que les attaquants ne puissent pas sonder le validateur. Utilisez le champ `code` (le code d'erreur lisible par machine) pour brancher dans votre logique cliente, et `trace_id` pour corréler avec les journaux serveur/audit (la ligne de journal porte la raison complète).

| Statut | `code` | Que corriger |
|---|---|---|
| `400` | `bad_request` | Paramètres de requête manquants/invalides, portée cible malformée ou non canonique, portée organisation non prise en charge, corps JSON invalide, ou permissions demandées que la politique de confiance n'autorise pas. |
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

Lorsque vous utilisez la `github-sts-action`, le jeton est révoqué automatiquement à la fin du job. Consultez [Cycle de vie du job]({{< relref "/integrations/github-action/job-lifecycle" >}}) pour plus de détails.

## Santé et préparation

| Point de terminaison | Méthode | Succès | Échec |
|---|---|---|---|
| `/health` | `GET` | `200` avec l'état de vivacité, la posture de sécurité et l'état des bundles configurés | `401` lorsque l'authentification de santé est configurée et que le jeton Bearer est absent ou incorrect |
| `/ready` | `GET` | `200` `{"ready":true}` | `503` `{"ready":false}` |
| `/metrics` | `GET` | Format texte Prometheus | `401` lorsque l'authentification des métriques est configurée et que le jeton Bearer est absent ou incorrect |

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
