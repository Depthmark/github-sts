---
title: Contribuer
description: Comment installer github-sts localement, ce que les vérifications imposent, et comment faire fusionner une modification.
weight: 2
translationKey: contributing
translationStatus: pending-review
---

Cette page reproduit le fichier [`CONTRIBUTING.md`](https://github.com/Depthmark/github-sts/blob/main/CONTRIBUTING.md) du dépôt, qui en est la copie de référence.

github-sts échange des jetons OIDC contre des jetons d'installation GitHub temporaires et limités. Comme il émet des identifiants, une modification ici peut élargir ce qu'un appelant est autorisé à faire. Cela façonne la façon dont les contributions sont examinées : l'exactitude et le rayon d'impact passent avant la commodité.

## Façons de contribuer

Ouvrez une issue pour tout ce que vous souhaitez voir changer. Les [modèles d'issue](https://github.com/Depthmark/github-sts/issues/new/choose) l'orientent au bon endroit :

- **Rapport de bogue** pour un comportement qui contredit la documentation.
- **Demande de fonctionnalité** pour une capacité qui n'existe pas encore.
- **Aide à la configuration** lorsqu'un échange est rejeté et que vous n'êtes pas certain qu'il s'agisse d'un défaut. La plupart des rejets viennent d'une politique de confiance ou d'une revendication qui ne correspond pas, plutôt que d'un bogue.
- **Problème de documentation** pour une page erronée, manquante, ou désynchronisée entre l'anglais et le français.

N'ouvrez jamais une issue publique pour une vulnérabilité. Voir [Sécurité](#security).

Pour tout ce qui dépasse une petite correction, ouvrez une issue avant d'écrire du code. Se mettre d'accord sur l'approche coûte moins cher que de réécrire une pull request.

## Environnement de développement

Il vous faut Go 1.26.6 ou plus récent, ainsi que l'outil dont dépend chaque vérification :

| Outil | Utilisé par | Installation |
|---|---|---|
| Go 1.26.6+ | `make build`, `make test` | [go.dev/dl](https://go.dev/dl/) |
| golangci-lint | `make lint` | [golangci-lint.run](https://golangci-lint.run/welcome/install/) |
| govulncheck | `make vuln-check` | `go install golang.org/x/vuln/cmd/govulncheck@latest` |
| OPA | `make test-rego` | [openpolicyagent.org](https://www.openpolicyagent.org/docs/latest/#running-opa) |
| check-jsonschema | `make validate-examples` | `pipx install check-jsonschema` |
| Docker | `make docker`, test OCI local | [docs.docker.com](https://docs.docker.com/get-docker/) |
| Hugo Extended | cibles de documentation | version épinglée dans `docs/.hugo-version` |
| Python 3 | vérifications de documentation | toute version 3.x |

Chaque cible qui a besoin d'un outil vérifie d'abord sa présence et vous indique quoi installer, ce qui vous permet de les ajouter au fur et à mesure plutôt que tous d'un coup.

## La boucle de développement

```bash
make build
make test          # ou : make test-race
make lint
make ci            # lint, tests race, tests Rego, contrôle de vulnérabilités, build, validation des exemples
```

`make ci` rassemble les vérifications Go en une seule commande. L'intégration continue exécute les mêmes outils via un workflow réutilisable partagé plutôt que via cette cible : un `make ci` propre laisse donc présager une pull request verte sans la garantir.

## Pull requests

Créez votre branche à partir de `main`. Les pull requests sont fusionnées en squash, donc **le titre de la pull request devient le message de commit**, et release-please lit ce message pour construire le journal des modifications et choisir la version suivante. Rédigez le titre comme un [Conventional Commit](https://www.conventionalcommits.org/fr/v1.0.0/) :

```text
feat: exchange tokens for enterprise-scoped installations
fix: reject expired OIDC tokens before policy evaluation
docs: document the bundle enforcement modes
feat!: rename GITHUBSTS_APP_ID to GITHUBSTS_APP_DEFAULT_APP_ID
```

Types utilisés : `feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`. Un `!` après le type signale une rupture de compatibilité ; décrivez le chemin de migration dans le corps de la pull request. Seuls `feat` et `fix` produisent une entrée de journal et un incrément de version.

Le modèle de pull request demande l'impact sur la publication, la façon dont vous avez testé, et les considérations de sécurité. Ces trois réponses sont ce qu'un relecteur lit en premier.

## Exemples de politiques de confiance

Deux ensembles de politiques sont validés contre `internal/policy/yaml/schema_v1.json` :

- `config/examples/*.sts.yaml`, vérifié par `make validate-examples`
- `.github/sts/*/*.sts.yaml`, les politiques que ce dépôt s'applique à lui-même, vérifiées par `make validate-repository-policies`

Chaque exemple de politique, dans le code comme dans la documentation, suit les règles d'exemple de `docs/documentation-contract.md` : uniquement des identifiants fictifs (`123456`, `myorg`, `stsexample.com`), une audience explicite sur chaque demande de jeton, des versions épinglées plutôt que `@main`, les autorisations minimales dont l'exemple a besoin, et `subject` plutôt que `subject_pattern` lorsqu'une correspondance exacte suffit.

## Documentation

L'anglais est la langue source et le français est obligatoire. Une page présente dans un arbre mais absente de l'autre fait échouer la construction.

```bash
make docs-serve    # http://localhost:1313/github-sts/
make docs-check    # construction, parité de traduction, liens et ancres, standard de rédaction
```

`make docs-check` et `.github/workflows/docs-check.yml` exécutent les mêmes contrôles dans le même ordre : une exécution locale propre signifie donc une vérification propre. Elle impose :

- **Parité :** chaque page existe dans les deux arbres, déclare `translationKey`, possède le même nombre de titres, et la version française atteint au moins 75 pour cent du nombre de mots de l'anglais.
- **Liens :** les liens internes et les ancres sont résolus contre le site construit, car Hugo valide la page cible d'un `relref` mais pas son fragment.
- **Standard de rédaction :** pas de tiret cadratin ni demi-cadratin dans la prose, pas d'emphase non justifiée, pas de formulation générique produite par une IA.

`docs/documentation-contract.md` fait autorité sur la structure, la terminologie, et la façon dont les dépôts satellites sont importés. Lisez-le avant toute restructuration.

## Workflows GitHub Actions

Épinglez chaque action et chaque workflow réutilisable à une empreinte de commit complète, avec le tag de version en commentaire de fin :

```yaml
uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
```

Un tag est mutable, et une action remplacée en amont s'exécute avec le jeton du job. Le dépôt est évalué par [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/Depthmark/github-sts), qui vérifie ce point.

## Sécurité {#security}

Signalez les vulnérabilités en privé via les [avis de sécurité GitHub](https://github.com/Depthmark/github-sts/security/advisories/new). N'ouvrez pas d'issue publique. Les délais de réponse et le processus de divulgation figurent sur la page [Sécurité]({{< relref "/resources/security" >}}).

Dans chaque modification, quelle que soit sa taille :

- Aucune clé privée, aucun jeton, aucun mot de passe et aucun point de terminaison de production réels dans le code, les tests, les fixtures ou la documentation.
- Aucune clé, aucun jeton et aucune revendication OIDC brute n'atteignant une ligne de journal, un message d'erreur ou une étiquette de métrique.
- Si une modification élargit la portée, la durée de vie ou l'audience d'un jeton émis, ou change les émetteurs et les revendications de confiance, signalez-le dans la pull request.

## Licence

github-sts est publié sous [licence MIT](https://github.com/Depthmark/github-sts/blob/main/LICENSE). Les contributions sont acceptées sous la même licence.
