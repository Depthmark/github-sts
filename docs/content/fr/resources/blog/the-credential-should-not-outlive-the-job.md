---
title: "L'identifiant ne devrait pas survivre à la tâche"
description: Pourquoi nous avons créé github-sts, ce qu'il remplace et ce qu'il coûte à exploiter.
date: 2026-09-21
authors: ["Alexandre Delisle"]
weight: 1
translationKey: credential-should-not-outlive-job
translationStatus: pending-review
---

*21 septembre 2026 · Alexandre Delisle*

## Créer un identifiant est facile. C'était le piège.

Créer un identifiant GitHub est facile. Ouvrez les paramètres, choisissez quelques permissions, copiez la valeur et placez-la dans un secret. C'est après que les choses se compliquent.

Chaque identifiant crée une petite obligation qui perdure. Quelqu'un doit savoir quelle tâche l'utilise, à quoi il donne accès, qui est responsable de sa rotation et ce qui cessera de fonctionner lorsqu'il sera révoqué. Le problème change de nature quand la réponse honnête à la question « combien en avons-nous? » devient « je dois écrire un script pour le savoir ».

C'est de là qu'est né github-sts. Pas d'une brèche, mais d'un problème d'inventaire.

Le mainteneur du projet parle de milliers de clés de déploiement, de comptes de service avec leur propre cycle de vie d'identité et de plus d'une centaine de GitHub Apps consommatrices réparties dans plusieurs organisations. Ces chiffres, fournis par le mainteneur, donnent une mesure de l'échelle et non un inventaire normalisé. Une GitHub App, une installation d'App et une clé privée d'App sont des objets différents. Une même App peut avoir plusieurs installations et plusieurs clés privées. Additionner ces nombres masquerait donc le travail au lieu de l'expliquer.

Aucun de ces mécanismes n'est un mauvais choix en soi. Chacun peut constituer une réponse locale sensée. Ensemble, ils sont devenus un système distribué de gestion des identifiants, assemblé une décision raisonnable à la fois.

Le coût récurrent venait de la coordination. Pour effectuer la rotation d'une clé, il fallait trouver chaque consommateur avant que l'ancienne clé cesse de fonctionner. Pour supprimer un compte de service, il fallait prouver qu'aucune tâche planifiée et discrète ne dépendait encore de ses appartenances. Un inventaire pouvait nous dire ce qui existait, mais pas toujours qui en avait encore besoin ni pourquoi sa portée était celle-là. L'organisation n'avait pas besoin d'un autre endroit où stocker des identifiants. Elle avait besoin d'une autre relation entre l'identité de la charge de travail et l'accès à GitHub.

## Comptez ce que votre jeton peut voir

Vous pouvez dresser un premier inventaire avec l'interface en ligne de commande GitHub (CLI). Authentifiez-vous d'abord, puis définissez l'organisation :

```bash
gh auth status
ORG=your-organization
```

[GitHub expose les clés de déploiement](https://docs.github.com/en/rest/deploy-keys/deploy-keys) par dépôt, et non au moyen d'un seul point de terminaison à l'échelle de l'organisation. Ce script affiche un total uniquement lorsque chaque requête visant un dépôt visible réussit :

```bash
set -euo pipefail

inventory="$(
  gh api --paginate "/orgs/$ORG/repos?type=all&per_page=100" --jq '.[].full_name' |
  while IFS= read -r repository; do
    printf 'repository\t%s\n' "$repository"
    gh api --paginate "/repos/$repository/keys?per_page=100" \
      --jq '.[] | "deploy-key\t\(.id)"' || exit 1
  done |
  awk -F '\t' '
    $1 == "repository" { repositories++ }
    $1 == "deploy-key" { deploy_keys++ }
    END { printf "repositories_seen=%d\ndeploy_keys=%d\n", repositories, deploy_keys }
  '
)"
printf '%s\n' "$inventory"
```

Le jeton doit disposer de la permission `Metadata: read` sur les dépôts pour les énumérer et de `Administration: read` pour répertorier les clés de déploiement. Il peut omettre silencieusement les dépôts privés qu'il ne peut pas voir. Comparez donc `repositories_seen` à un inventaire de référence. Le script effectue aussi au moins une requête API par dépôt.

Comptez séparément les installations d'App :

```bash
gh api "/orgs/$ORG/installations?per_page=1" --jq '.total_count'
```

[Cet appel](https://docs.github.com/en/rest/orgs/orgs#list-app-installations-for-an-organization) exige un accès de propriétaire de l'organisation, ou un jeton à granularité fine doté de la permission d'organisation `Administration: read`. Son résultat compte les installations, et non les Apps ni les clés privées. GitHub ne fournit pas non plus de champ API fiable pour distinguer les comptes machine des personnes. Cet inventaire exige donc une convention propre à l'organisation pour les noms ou la propriété.

## Utilisez le mécanisme le plus simple qui convient

[`GITHUB_TOKEN`](https://docs.github.com/en/actions/concepts/security/github_token) est la bonne réponse pour de nombreux workflows. GitHub l'émet pour la tâche, ses permissions peuvent être restreintes et aucune clé permanente ne doit être distribuée. Si un workflow agit uniquement sur son propre dépôt, commencez par là.

Une clé privée de GitHub App utilisée avec [`actions/create-github-app-token`](https://github.com/actions/create-github-app-token) constitue aussi une bonne option pour l'automatisation entre dépôts qui ne justifie pas un autre service. Elle produit un jeton d'installation temporaire doté de l'identité et des permissions de l'App. En contrepartie, le workflow autorisé peut lire la clé privée permanente qui sert à créer ce jeton. La rotation et la distribution restent à la charge de chaque magasin de secrets qui détient la clé.

github-sts s'adresse au moment où cette distribution devient le problème. Il retire la clé privée de l'App des charges de travail et la place dans un broker que vous exploitez.

## Identité, politique, jeton

[L'OIDC pour le nuage](https://docs.github.com/en/actions/concepts/security/openid-connect) a établi un modèle d'échange utile : une charge de travail peut présenter une preuve temporaire de son identité au lieu de recevoir un secret permanent. [Octo STS](https://github.com/octo-sts/app) a été l'une des premières mises en œuvre de cette idée pour les identifiants GitHub et a directement inspiré github-sts.

Le modèle sépare trois décisions :

1. OIDC prouve quelle charge de travail fait la demande.
2. La politique décide ce que cette charge de travail peut demander.
3. GitHub émet l'identifiant qui en résulte.

Cette séparation compte. Une date d'expiration limite la durée d'utilisation d'un jeton volé. Elle n'explique pas pourquoi la charge de travail était autorisée à recevoir ce jeton au départ.

Voici une tâche représentative de synchronisation d'étiquettes, avec des SHA de commit complets vérifiés pour les versions indiquées :

```yaml
name: Sync labels
on:
  schedule:
    - cron: '0 6 * * 1'

jobs:
  sync:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: Depthmark/github-sts-action@9014c80f47cad81e0a1295b112714d5c1b219d54 # v0.3.0
        id: sts
        with:
          sts-url: https://sts.example.com
          audience: https://sts.example.com
          scope: myorg/service-a
          identity: label-sync

      - name: Apply the shared label
        env:
          GH_TOKEN: ${{ steps.sts.outputs.token }}
        run: >-
          gh label create needs-triage
          --repo myorg/service-a
          --description "Awaiting triage"
          --color FBCA04
          --force
```

Le chemin d'authentification ne contient aucune référence à `secrets.`. `id-token: write` permet à la tâche de demander un jeton d'identité OIDC. github-sts valide cette preuve, évalue la politique et demande à GitHub un jeton d'installation distinct. La charge de travail ne reçoit jamais la clé privée d'App du broker, le JWT de l'App ni le jeton de lecture des politiques.

Les entrées `scope` et `identity` désignent la décision d'autorisation, et non un simple modèle de jeton. Dans cet exemple, le dépôt cible peut définir `.github/sts/default/label-sync.sts.yaml` afin de nommer le workflow source approuvé et de n'accorder que `issues: write`. Si la charge de travail demande des permissions qui dépassent ce plafond, l'échange est refusé. La politique demeure révisable à côté du dépôt qu'elle protège. Un dépôt de politiques d'organisation peut toutefois en devenir responsable lorsqu'une équipe centrale doit prendre la décision.

## La voie choisie par github-sts

Chaque échange sélectionne une politique de confiance YAML, soit dans le dépôt cible, soit dans un dépôt de politiques d'organisation configuré. `org_first` est le mode de résolution par défaut. La politique centralisée l'emporte donc lorsque les deux emplacements définissent la même identité. La politique lie la requête à un émetteur, à une audience obligatoire, aux revendications de la charge de travail, aux permissions autorisées ainsi qu'aux relations exactes entre la source et la cible.

L'ordre des vérifications est intentionnel. Le broker valide l'émetteur OIDC, la signature, les revendications temporelles et l'audience avant que la politique puisse autoriser quoi que ce soit. Il vérifie ensuite l'identité GitHub, rejette un `jti` réutilisé, résout l'App demandée et le dépôt cible exact, charge une politique, évalue les revendications et les relations, applique les garde-fous d'entreprise lorsqu'ils sont configurés, puis demande enfin à GitHub de créer un jeton. L'échec d'une vérification interrompt l'échange. Le jeton OIDC reste une preuve du début à la fin. Il n'est jamais transformé en identifiant GitHub.

Pour GitHub.com, ces relations utilisent les identifiants numériques immuables du propriétaire et du dépôt. Les noms peuvent changer ou être réutilisés. Grâce aux identifiants, le renommage d'un dépôt ne devient pas un changement d'autorisation.

Le broker réserve également le `jti` de chaque jeton OIDC pour rejeter le rejeu. Le backend en mémoire convient à un seul réplica. Les déploiements à plusieurs réplicas exigent `GITHUBSTS_JTI_BACKEND=redis` afin que chaque réplica partage l'état de rejeu.

La `scope` demandée doit désigner exactement un dépôt. Une portée de jeton à l'échelle de l'organisation est délibérément refusée. Une charge de travail qui a besoin de trois dépôts effectue trois échanges et reçoit trois jetons aux portées distinctes. Cette approche est plus verbeuse, mais elle garde chaque attribution explicite.

Les bundles Rego d'entreprise peuvent ajouter un plafond central au-dessus de la politique YAML sélectionnée. Ce sont des artefacts OCI épinglés par empreinte, vérifiés par cosign et additifs, où le refus l'emporte. Dans la posture recommandée `bundle_enforcement: required`, une base de référence globale est obligatoire et bloque en cas d'échec. La politique du dépôt ne peut pas l'affaiblir. La [documentation sur l'architecture]({{< relref "/concepts/architecture" >}}) décrit la séquence d'autorisation ordonnée complète.

## La complexité s'est déplacée

github-sts ne fait pas disparaître les secrets à longue durée de vie. Le broker détient toujours une ou plusieurs clés privées de GitHub App. Il concentre cette autorité afin que les charges de travail ne puissent pas la lire. Cela concentre aussi les conséquences d'une compromission du broker.

Les opérateurs sont responsables de TLS, de la disponibilité, des mises à niveau, de la rotation des clés, de la surveillance et de la réponse aux incidents. Le broker se trouve sur le chemin d'authentification. Une panne empêche donc les tâches qui en dépendent de recevoir des jetons. Les bundles obligatoires peuvent bloquer l'accès s'ils ne peuvent pas être vérifiés ou s'ils dépassent l'âge défini par `max_staleness`. L'émission des événements d'audit est asynchrone et mise en mémoire tampon. Les opérateurs devraient donc [créer des alertes sur les événements perdus et les erreurs d'écriture]({{< relref "/integrations/monitor-usage" >}}), plutôt que de présumer que chaque événement a été enregistré.

C'est le compromis. De nombreux cycles de vie distribués d'identifiants deviennent un seul périmètre opérationnel sensible sur le plan de la sécurité. La pertinence de cet échange dépend du parc que vous avez recensé au début.

Nous ne disposons pas encore d'un chiffre reproductible sur les heures de rotation économisées ou le nombre d'identifiants retirés. Il s'agit donc d'un critère de conception, et non d'une victoire proclamée. La question utile est concrète : la centralisation de l'autorité a-t-elle éliminé assez de travail distribué lié à la propriété, au stockage et à la rotation pour justifier l'exploitation du broker? Les équipes qui ne comptent qu'une poignée de workflows peuvent raisonnablement répondre non. Celles qui n'arrivent plus à expliquer leur inventaire d'identifiants peuvent répondre autrement.

L'identifiant ne devrait pas survivre à la tâche. La décision d'autorisation ne devrait pas disparaître lorsque la tâche se termine non plus. Une date d'expiration répond à la première exigence. L'identité et la politique sont ce qui permet de répondre à la seconde.
