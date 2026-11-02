---
title: GitHub Actions
description: Configurez github-sts pour valider les jetons OIDC émis par GitHub Actions.
weight: 1
translationKey: oidc-issuers-github-actions
translationStatus: pending-review
---

Cas le plus courant pour ce service. Aucune substitution d'hôte JWKS requise.

| Champ | Valeur |
|---|---|
| Émetteur | `https://token.actions.githubusercontent.com` |
| Découverte | `https://token.actions.githubusercontent.com/.well-known/openid-configuration` |
| Hôte `jwks_uri` | `token.actions.githubusercontent.com` (identique à l'émetteur) |
| `kid` dans les jetons | Toujours présent |
| Substitution requise | **Non** |

```yaml
oidc:
  allowed_issuers:
    - https://token.actions.githubusercontent.com
  require_immutable_subject_claims: true # valeur par défaut sécurisée
  # trusted_jwks_hosts: inutile
```

Pour GitHub.com, github-sts exige des revendications signées de type chaîne pour
`repository_owner`, `repository_owner_id`, `repository` et `repository_id`. Il
recoupe ces valeurs avec le sujet du jeton avant de vérifier l'audience, le
rejeu ou de chercher la politique.

Par défaut, le sujet doit contenir les identifiants immuables :

```text
repo:OWNER@OWNER-ID/REPO@REPO-ID:ref:refs/heads/BRANCH
```

Les dépôts créés avant le 15 juillet 2026 conservent l'ancien format, limité aux
noms, tant qu'ils n'ont pas activé le nouveau format par le réglage OIDC d'Actions
de l'organisation ou du dépôt, ou par l'API REST. Définissez
`require_immutable_subject_claims: false` uniquement comme posture explicite de
migration. Les revendications distinctes d'identifiants immuables restent
obligatoires. Cette fonctionnalité concerne uniquement GitHub.com et n'est pas
disponible sur GitHub Enterprise Server.

### Obtenir les identifiants immuables du propriétaire et du dépôt

Les politiques de confiance (`github.sources[]` / `github.target`, voir
[Politiques de confiance]({{< relref "/concepts/trust-policies" >}})) et les
exceptions inter-organisations d'entreprise utilisent les valeurs numériques
`owner_id` / `repository_id`, pas les noms. Récupérez-les avec l'API GitHub avant
d'écrire la politique : aucun échange de jeton n'est requis.

```bash
# Dépôts source et cible : owner_id + repository_id en un seul appel.
gh api repos/OWNER/REPO --jq '{owner_id: (.owner.id | tostring), repository_id: (.id | tostring)}'
# → {"owner_id":"123456","repository_id":"456789"}
```

Sans `gh`, voici l'équivalent avec `curl` (un jeton GitHub n'est nécessaire que
pour les dépôts privés) :

```bash
curl -fsS -H "Authorization: Bearer $GITHUB_TOKEN" \
  "https://api.github.com/repos/OWNER/REPO" \
  | jq '{owner_id: (.owner.id | tostring), repository_id: (.id | tostring)}'
```

Les champs d'une politique de confiance sont des chaînes (`"123456"`, pas
`123456`). Mettez entre guillemets les valeurs issues de `jq` lorsque vous les
collez dans le YAML.

Une fois qu'un workflow a activé les sujets immuables, confirmez que le jeton OIDC
émis porte bien les mêmes identifiants (voir
[Dépannage]({{< relref "/operations/troubleshooting" >}}) pour la commande de
décodage) :

```bash
echo "$OIDC_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null \
  | jq '{sub, repository_owner_id, repository_id}'
```

Si `repository_owner_id` / `repository_id` sont absents du jeton décodé, le dépôt
n'a pas encore activé les revendications immuables. Activez-les par le réglage
« OIDC customization » d'Actions du dépôt ou de l'organisation (ou par l'API REST
équivalente) avant de vous appuyer sur les correspondances `github.sources[]` /
`github.target`.

Vérifier :

```bash
curl -fsS https://token.actions.githubusercontent.com/.well-known/openid-configuration \
  | jq -r .jwks_uri
# → https://token.actions.githubusercontent.com/.well-known/jwks
```

## Accepter les jetons d'un émetteur d'entreprise GitHub.com {#enterprise-issuer}

Permettez à une entreprise GitHub Enterprise Cloud d'atteindre les Apps de votre choix par son propre émetteur. Un propriétaire de l'entreprise peut demander à GitHub d'ajouter le slug de l'entreprise à `iss`. Une politique qui nomme cet émetteur correspond alors aux seuls jetons de cette entreprise, et non à ceux de tous les dépôts GitHub.com.

**1. Déclarez l'émetteur.** Inscrivez-le aux deux endroits et nommez les Apps qu'il peut atteindre :

```yaml
oidc:
  allowed_issuers:
    - https://token.actions.githubusercontent.com
    - https://token.actions.githubusercontent.com/myorg-enterprise
  github_issuers:
    - issuer: https://token.actions.githubusercontent.com/myorg-enterprise
      apps:
        - deploy
```

L'émetteur partage les clés de l'émetteur par défaut sur le même hôte : il ne demande donc aucune entrée `trusted_jwks_hosts`. Conservez l'émetteur par défaut dans `allowed_issuers` tant qu'une charge de travail l'utilise.

**2. Écrivez la politique de confiance pour cet émetteur.** Un émetteur déclaré exige le bloc `github`, comme l'émetteur par défaut :

```yaml
issuer: https://token.actions.githubusercontent.com/myorg-enterprise
audience: https://sts.example.com
subject: repo:myorg@123456/myrepo@456789:ref:refs/heads/main
github:
  sources:
    - owner_id: "123456"
      repository_id: "456789"
  target:
    owner_id: "123456"
    repository_id: "456789"
permissions:
  contents: read
```

Une politique nomme exactement un émetteur. Dès que GitHub bascule l'entreprise, une politique qui nomme encore l'émetteur par défaut refuse ses jetons avec `policy_denied` : prévoyez donc les étapes 2 et 3 dans la même fenêtre.

**3. Activez l'émetteur dans GitHub.** Un propriétaire de l'entreprise exécute cette commande avec un jeton d'accès personnel classique ou un jeton d'application OAuth doté de la portée `admin:enterprise`. GitHub répond `204` :

```bash
gh api --method PUT /enterprises/myorg-enterprise/actions/oidc/customization/issuer \
  -F include_enterprise_slug=true
```

**4. Confirmez avec un vrai jeton.** Décodez-en un issu d'une exécution de workflow. Ne vous fiez pas au document de découverte pour cela : GitHub répond `200` pour n'importe quel slug, y compris un slug qui n'existe pas.

```bash
echo "$OIDC_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null \
  | jq '{iss, sub, repository_owner_id, repository_id}'
```

### Ce que github-sts impose à un émetteur déclaré

| Contrôle | Comportement | Échec |
|---|---|---|
| Identité | Les mêmes vérifications des revendications signées que pour l'émetteur par défaut, avant l'audience, le rejeu ou la politique. | `github_identity_invalid` |
| Sujet immuable | Toujours exigé. `require_immutable_subject_claims: false` ne s'applique qu'à l'émetteur par défaut et ne peut donc pas assouplir un émetteur déclaré. Les dépôts créés avant le 15 juillet 2026 doivent d'abord activer ce format. | `github_identity_invalid` |
| Portée par App | L'App résolue pour la requête doit figurer sous `apps`. github-sts refuse le jeton avant tout appel à GitHub, quoi que dise la politique. | `issuer_not_enabled` |
| Source et cible | La politique doit lister les identifiants exacts `github.sources[]` et `github.target`, comme pour l'émetteur par défaut. | `policy_denied` |
| Configuration | Le démarrage échoue et nomme le champ pour un émetteur d'une autre forme, une App inconnue ou manquante, un doublon, ou un émetteur absent de `allowed_issuers`. | Le serveur ne démarre pas |

Un émetteur d'entreprise inscrit seulement dans `allowed_issuers` reste un émetteur générique. Ses jetons ne subissent aucune vérification d'identité GitHub, ses politiques ne peuvent pas utiliser le bloc `github`, et le serveur journalise un avertissement au démarrage. Déclarez-le pour combler cet écart.

Rego reçoit l'URL de l'entreprise dans `source_identity.issuer`. Une base de référence qui fixe l'émetteur par défaut, comme `policies/example_enterprise_baseline.rego`, refuse ces jetons tant que vous n'y ajoutez pas l'émetteur.

### Autres émetteurs GitHub

Seule la première ligne de ce tableau peut être déclarée. `oidc.github_issuers` refuse les autres au démarrage, car leurs identifiants ou leurs sujets diffèrent de ceux de GitHub.com. Inscrits seulement dans `allowed_issuers`, ils restent des émetteurs génériques, sans vérification d'identité GitHub.

| Produit | Émetteur | Déclaré dans `oidc.github_issuers` |
|---|---|---|
| GitHub Enterprise Cloud sur GitHub.com | `https://token.actions.githubusercontent.com/<enterprise-slug>` | Oui |
| GitHub Enterprise Cloud sur GHE.com | `https://token.actions.<subdomain>.ghe.com/<subdomain>` | Non : l'entreprise a sa propre instance et ses propres identifiants |
| GitHub Enterprise Server | `https://<hostname>/_services/token` | Non : les identifiants viennent d'une autre instance, et il n'a pas de sujet immuable |
