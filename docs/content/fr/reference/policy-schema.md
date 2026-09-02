---
title: Schéma des politiques de confiance
description: Schéma JSON publié pour les fichiers de politique de confiance, configuration de l'éditeur, validation en ligne de commande et limites de la validation structurelle.
weight: 5
translationKey: policy-schema
translationStatus: pending-review
---

github-sts publie un schéma JSON pour les fichiers de politique de confiance.
Configurez votre éditeur pour l'utiliser et les fichiers `.sts.yaml` sont
validés pendant la saisie, avec complétion des noms de champs et des valeurs de
permission.

## URL du schéma

```
https://depthmark.github.io/github-sts/schemas/sts/v1/trust-policy.json
```

Le schéma décrit le format documenté dans
[Politiques de confiance]({{< relref "/concepts/trust-policies" >}}), à savoir
les fichiers stockés dans `.github/sts/{app}/{identity}.sts.yaml`.

Il s'agit d'un fichier statique servi par le site de documentation. Il ne
nécessite ni broker en cours d'exécution, ni authentification. C'est un
artefact distinct du point de terminaison `GET /sts/v1/trust-policy.json`
décrit dans la [Référence API]({{< relref "/reference/api" >}}), qui republie le
schéma fourni par le bundle Rego chargé et s'adresse aux opérateurs d'un bundle
de politiques personnalisé.

## Configuration de l'éditeur

### Par fichier

Ajoutez un commentaire en première ligne du fichier de politique. Les éditeurs
qui s'appuient sur le serveur de langage YAML le lisent, ce qui couvre VS Code
avec l'extension YAML de Red Hat, IntelliJ IDEA, Neovim avec `yamlls` et Zed.

```yaml
# yaml-language-server: $schema=https://depthmark.github.io/github-sts/schemas/sts/v1/trust-policy.json
issuer: https://token.actions.githubusercontent.com
audience: https://sts.example.com
subject: "repo:myorg/myrepo:ref:refs/heads/main"
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

Ce commentaire est inerte lors de l'échange de jeton. Le broker analyse les
champs, pas les commentaires.

### Par espace de travail

Pour valider tous les fichiers de politique sans modifier chacun d'eux,
associez le schéma par chemin dans `.vscode/settings.json` :

```json
{
  "yaml.schemas": {
    "https://depthmark.github.io/github-sts/schemas/sts/v1/trust-policy.json": "**/*.sts.yaml"
  }
}
```

Le motif est comparé au chemin complet du document ouvert : commencez-le donc
par `**/` plutôt que par un fragment relatif à l'espace de travail. Pour
restreindre l'association davantage que ne le fait le suffixe du fichier,
utilisez `**/.github/sts/*/*.sts.yaml`.

## Ligne de commande

```bash
pipx install check-jsonschema

check-jsonschema \
  --schemafile https://depthmark.github.io/github-sts/schemas/sts/v1/trust-policy.json \
  .github/sts/*/*.sts.yaml
```

## Intégration continue

Contrôlez les modifications de politique avec le schéma avant qu'elles
n'atteignent le broker. Une politique mal formée qui est fusionnée n'est
détectée que lorsqu'une charge de travail tente un échange de jeton et reçoit
une réponse `403`.

```yaml
name: Validate trust policies

on:
  pull_request:
    paths:
      - '.github/sts/**'

permissions: {}

jobs:
  schema:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - run: pipx install check-jsonschema
      - run: |
          check-jsonschema \
            --schemafile https://depthmark.github.io/github-sts/schemas/sts/v1/trust-policy.json \
            .github/sts/*/*.sts.yaml
```

## Ce que le schéma vérifie

| Règle | Détail |
|---|---|
| Champs obligatoires | `issuer`, `audience` et `permissions` doivent être présents |
| Champs inconnus | Tout champ hors de l'ensemble documenté est rejeté |
| Sélecteur d'identité | Au moins un parmi `subject`, `subject_pattern` ou `claim_pattern` |
| Conflit de sélecteurs | `subject` et `subject_pattern` sont mutuellement exclusifs |
| Liaison GitHub | `github` est obligatoire pour l'émetteur GitHub Actions et interdit pour tout autre émetteur |
| Noms de permissions | Uniquement les noms de permissions acceptés par GitHub pour les jetons d'installation |
| Valeurs de permissions | Les niveaux acceptés par GitHub pour cette permission précise, et non un ensemble uniforme |
| Identifiants immuables | `owner_id` et `repository_id` doivent être des chaînes décimales non nulles entre guillemets |
| Sources en double | Les entrées de `github.sources` doivent être uniques |

## Ce que le schéma ne vérifie pas

Un schéma JSON valide une structure. Plusieurs règles appliquées par le broker
ne peuvent pas s'exprimer structurellement, si bien qu'un fichier conforme au
schéma peut malgré tout être rejeté lors de l'échange :

- **Validité des expressions régulières.** Les valeurs de `subject_pattern` et
  de `claim_pattern` sont compilées par le broker comme des expressions RE2
  ancrées. Un motif syntaxiquement correct en YAML mais invalide comme
  expression échoue seulement au chargement de la politique par le broker.
- **Existence des identifiants.** `owner_id` et `repository_id` sont vérifiés
  quant à leur forme, pas à leur existence. Une faute de frappe qui reste
  numérique passe le schéma, puis ne correspond pas au jeton présenté.
- **Garde-fous d'entreprise.** Les bundles Rego appliquent des plafonds de
  permissions et des règles de refus à l'échelle de l'organisation. Ils sont
  évalués pendant l'échange, en fonction de la requête, et restent invisibles
  pour un schéma.
- **État de l'installation.** Le fait que la GitHub App soit installée sur le
  dépôt cible avec les permissions accordées par la politique.

### Les niveaux dépendent de chaque permission

Il n'existe pas d'ensemble unique de niveaux. GitHub accepte `read` ou `write`
pour la plupart des permissions, `admin` pour quatre d'entre elles seulement
(`organization_custom_properties`, `organization_projects`,
`repository_projects` et `enterprise_custom_properties_for_organizations`),
`read` seul pour `organization_events` et `organization_plan`, et `write` seul
pour `profile` et `workflows`.

Le schéma encode l'ensemble propre à chaque permission : `contents: admin` et
`workflows: read` sont donc rejetés pendant la rédaction du fichier, plutôt que
par l'API GitHub avec une réponse `422` lors du premier échange de jeton par une
charge de travail. La source est la description OpenAPI publiée par GitHub, plus
précisément le schéma `app-permissions` déclaré par le corps de requête de
create-installation-access-token. Les mainteneurs peuvent comparer les deux avec
`make check-github-permissions`.

Deux remarques supplémentaires portent sur les messages plutôt que sur les
résultats. Un champ `repositories` non pris en charge est rejeté comme champ
inconnu, alors que le broker précise que les portées au niveau de
l'organisation sont désactivées. Définir une permission à `none` est rejeté
dans les deux cas ; omettez plutôt la clé, car c'est ainsi que ce format
exprime une permission non accordée.

Pour les règles ci-dessus qu'un schéma ne peut pas atteindre, envoyez la
politique au point de terminaison `POST /sts/v1/trust-policy/validate` du
broker, documenté dans la [Référence API]({{< relref "/reference/api" >}}). Il
exécute la même validation que le chemin d'échange et renvoie des diagnostics
avec numéros de ligne et de colonne.

## Stabilité

Le chemin `v1` n'accepte que des modifications additives. De nouveaux champs
optionnels et de nouveaux noms de permissions peuvent apparaître. Aucun champ
n'est supprimé, aucun champ ne devient obligatoire et aucun motif n'est
resserré. Une modification qui casserait les politiques existantes est publiée
sous un chemin `v2`, et `v1` continue d'être servi.

Le schéma est issu du code source du broker et publié par la construction de la
documentation, et des tests verrouillent sa liste de permissions sur celle que
le broker applique. Une permission acceptée par le schéma est une permission
acceptée par le broker.
