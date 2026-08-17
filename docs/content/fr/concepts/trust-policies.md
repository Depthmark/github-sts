---
title: Politiques de confiance
description: Comprenez les concepts des politiques de confiance, les définitions de champs et les exemples sécurisés.
weight: 3
translationKey: trust-policies
translationStatus: pending-review
---

Les politiques de confiance sont des fichiers YAML stockés **dans le dépôt cible** qui définissent quelles identités OIDC peuvent demander des jetons et avec quelles autorisations.

**Emplacement :** `.github/sts/{app_name}/{identity}.sts.yaml`

Pour `app=my-app` et `identity=ci`, le chemin se résout en `.github/sts/my-app/ci.sts.yaml`.

## Schéma de politique

| Champ | Type | Description |
|---|---|---|
| `issuer` | `string` | Revendication OIDC `iss` (correspondance exacte) |
| `subject` | `string` | Revendication OIDC `sub` (correspondance exacte) |
| `subject_pattern` | `regex` | Revendication OIDC `sub` (regex, utilisée lorsque `subject` est absent) |
| `claim_pattern` | `map[string]regex` | Revendications JWT supplémentaires à faire correspondre |
| `audience` | `string` | **Obligatoire.** Revendication OIDC `aud` attendue. Une politique sans elle accepterait des jetons émis pour toute autre relying party partageant l'émetteur (réutilisation de jeton inter-RP) et est rejetée à l'analyse. |
| `repositories` | `list[string]` | Présent dans le schéma mais non appliqué dans le flux d'échange. La portée de dépôt fixe le jeton au dépôt demandé ; les politiques d'organisation centralisées le fixent au seul dépôt dérivé du sujet OIDC. |
| `permissions` | `map[string]string` | Autorisations de la GitHub App (`read` / `write` / `admin`) |

> **`audience` est obligatoire.** Chaque politique doit déclarer l'audience OIDC à laquelle elle fait confiance. La même valeur doit être transmise à `core.getIDToken(<audience>)` dans le workflow qui demande le jeton. Une `audience:` manquante est rejetée à l'analyse de la politique ; sinon, elle accepterait des jetons émis pour toute autre relying party partageant l'émetteur (réutilisation de jeton inter-RP).

## Correspondance du sujet

Les politiques prennent en charge deux méthodes pour faire correspondre la revendication OIDC `sub` :

### Correspondance exacte (recommandée)

Utilisez `subject` pour une correspondance littérale et exacte. C'est l'option la plus sûre.

```yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:org/repo:ref:refs/heads/main
audience: https://sts.example.com
permissions:
  contents: read
```

### Expression régulière

Utilisez `subject_pattern` lorsque vous devez faire correspondre une plage de sujets (par exemple, toutes les branches, plusieurs dépôts).

```yaml
issuer: https://token.actions.githubusercontent.com
subject_pattern: "repo:org/repo:.*"
audience: https://sts.example.com
permissions:
  contents: read
```

> Préférez `subject` dès que possible. Une correspondance exacte supprime l'ambiguïté d'une large regex et rend la portée de la politique explicite.

## Modèles de revendications

`claim_pattern` est un mappage de noms de revendications JWT vers des expressions régulières. Utilisez-le pour exiger des contraintes d'identité supplémentaires au-delà de `iss` et `sub`.

```yaml
issuer: https://token.actions.githubusercontent.com
subject_pattern: "repo:org/repo:.*"
audience: https://sts.example.com
claim_pattern:
  job_workflow_ref: "org/repo/.github/workflows/deploy\\.yml@.*"
  repository_owner: "^myorg$"
permissions:
  deployments: write
```

Cette politique ne correspond qu'aux workflows provenant de `deploy.yml` dans l'organisation `myorg`.

### Revendications personnalisées

GitHub Actions vous permet d'attacher des revendications personnalisées au jeton OIDC, y compris les [propriétés personnalisées](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect#customizing-the-token-claims) du dépôt. Vous pouvez exiger ces revendications avec `claim_pattern` pour épingler les politiques à un environnement, un déploiement ou une propriété métier spécifique :

```yaml
issuer: https://token.actions.githubusercontent.com
subject_pattern: "repo:myorg/.*"
audience: https://sts.example.com
claim_pattern:
  repository_owner: "^myorg$"
  environment: "^production$"
permissions:
  deployments: write
```

Pour en savoir plus sur les revendications de jeton OIDC de GitHub, voir :

- [About security hardening with OpenID Connect](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [Immutable subject claims for GitHub Actions OIDC tokens](https://github.blog/changelog/2026-04-23-immutable-subject-claims-for-github-actions-oidc-tokens/)

## Portée d'organisation

En plus de la portée de dépôt (`scope=org/repo`), github-sts prend en charge la **portée d'organisation** (`scope=myorg`).

Configurez `org_policy_repo` pour indiquer où vivent les politiques d'organisation :

```yaml
apps:
  default:
    app_id: 123456
    private_key_path: /etc/github-sts/keys/default.pem
    org_policy_repo: .github
```

Exemple de politique d'organisation (placée dans `myorg/.github/.github/sts/default/org-ci.sts.yaml`) :

```yaml
issuer: https://token.actions.githubusercontent.com
subject_pattern: "repo:myorg/.*"
audience: https://sts.example.com
permissions:
  contents: read
  pull_requests: write
```

> Une politique d'organisation centralisée fixe le jeton émis au seul dépôt dérivé de la revendication OIDC `sub` ; elle n'accorde pas un accès à l'échelle de l'organisation.

### Résolution de politique

Lorsque la même identité possède un fichier de politique à la fois dans le dépôt demandeur et dans le dépôt de politiques d'organisation, `policy_resolution` détermine lequel l'emporte :

| Mode | Ordre | En cas de collision | Utiliser lorsque |
|---|---|---|---|
| `org_first` *(par défaut)* | org → repli dépôt | **l'organisation l'emporte** | L'admin de l'organisation possède les noms d'identité ; les dépôts peuvent auto-gérer les identités non revendiquées par l'organisation. |
| `repo_first` *(obsolète)* | dépôt → repli org | le dépôt l'emporte | Rétrocompatibilité uniquement ; permet aux propriétaires de dépôt de remplacer la politique centralisée. Émet un avertissement d'obsolescence au démarrage. |
| `org_only` | dépôt d'organisation uniquement, sans repli | n/a | Interdire strictement l'auto-gestion. Les dépôts ne peuvent pas définir leurs propres politiques. |

```yaml
apps:
  default:
    app_id: 123456
    private_key_path: /etc/github-sts/keys/default.pem
    org_policy_repo: .github
    policy_resolution: org_first
```

Si `org_policy_repo` n'est pas défini, seul le dépôt demandeur est consulté, quel que soit le mode.

## Étapes suivantes

- [Recettes de politiques]({{< relref "/concepts/policy-recipes" >}}): modèles à copier-coller pour les scénarios courants
- [Émetteurs OIDC]({{< relref "/oidc-issuers" >}}): configuration par fournisseur
- [Modèle de sécurité]({{< relref "/concepts/security-model" >}}): limites de confiance et modèle de menace
