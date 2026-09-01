---
title: Publier des bundles signés
description: Versions minimales de cosign et du registre pour un bundle de politique vérifiable, avec des exemples de publication pour GHCR, Harbor, Nexus et Artifactory.
weight: 7
translationKey: publishing-bundles
translationStatus: pending-review
---

`github-sts` vérifie exactement un format de signature : un bundle Sigstore
standardisé stocké en référent OCI 1.1. Cette page décrit les versions qui le
produisent et comment en publier un vers quatre registres courants.

Voir [Compatibilité]({{< relref "/integrations/compatibility" >}}) pour ce qui
se passe lorsqu'un bundle est signé autrement.

## Versions minimales

### Cosign

| Version | Résultat |
|---|---|
| v3.0.0 et ultérieures | Produit le format pris en charge par défaut. Recommandé |
| v2.6.5 | Ne le produit qu'avec `--new-bundle-format=true`. Testé et accepté |
| v2.x par défaut | Produit le tag historique `sha256-<digest>.sig`, qui n'est pas vérifié |

Cosign v3 a basculé `--new-bundle-format` à true par défaut et déprécié
l'option. En pratique, le format écrit dépend donc de la version majeure de
cosign : **épinglez cosign dans la chaîne de publication**. Un `cosign` non
épinglé dans `$PATH`, ou la valeur par défaut d'une action d'installation,
décide silencieusement si le bundle publié pourra être vérifié.

### Registre

Le registre doit accepter un manifeste d'image OCI 1.1 portant un champ
`subject`. L'API Referrers d'OCI est préférable mais pas obligatoire :
`github-sts` bascule sur le schéma de tag de référents lorsqu'un registre ne
l'implémente pas.

| Registre | Version minimale | Remarques |
|---|---|---|
| GitHub Container Registry | Sans objet, hébergé | API Referrers prise en charge en lecture et en écriture |
| Harbor | 2.8 a introduit la prise en charge de la distribution OCI 1.1, étendue jusqu'à 2.9 | Vérifié sur 2.15. L'interface Harbor peut étiqueter une signature cosign v3 comme un type d'accessoire inconnu ; c'est un problème d'affichage sans effet sur la vérification |
| JFrog Artifactory | 7.90.1 | API Referrers ajoutée dans cette version |
| Sonatype Nexus Repository | 3.94.0 | Les dépôts OCI, avec la prise en charge de l'API Referrers, sont nouveaux dans cette version |

Les numéros de version évoluent et les éditeurs rétroportent. Traitez ce tableau
comme un point de départ et confirmez avec la sonde ci-dessous plutôt que de lui
faire confiance.

## Vérifier votre registre avant de vous y fier

Publiez et signez un artefact jetable, puis relisez ce que le registre a
réellement stocké. Cela prend une minute et répond à la question que le tableau
de versions ne fait qu'estimer.

```bash
REF="<registre>/<chemin>/probe:$(date +%s)"
echo probe > probe.txt
crane append --oci-empty-base --new_layer probe.txt --new_tag "$REF"
DIGEST="$(crane digest "$REF")"
cosign sign --key cosign.key --yes "${REF%%:*}@${DIGEST}"

# Demander les référents. Un index JSON signifie que l'API Referrers est active.
curl -s -H "Accept: application/vnd.oci.image.index.v1+json" \
  "https://<registre>/v2/<chemin>/probe/referrers/${DIGEST}"

# Un 404 ci-dessus est acceptable : le repli par tag est utilisé, donc regardez ici :
curl -s "https://<registre>/v2/<chemin>/probe/manifests/${DIGEST/:/-}"
```

L'une des deux réponses doit lister un manifeste dont le type de média de couche
est `application/vnd.dev.sigstore.bundle.v0.3+json`. Si aucune ne le fait, le
registre n'a pas stocké la signature sous une forme que `github-sts` peut
trouver.

Le descripteur de l'index de repli peut indiquer `artifactType` comme
`application/vnd.oci.empty.v1+json` plutôt que le type du bundle. C'est une
limitation connue de cosign sur les registres sans API Referrers. `github-sts`
récupère chaque manifeste de référent au lieu de se fier à la liste, si bien que
la signature reste trouvée.

## Construire le bundle

Identique pour tous les registres. Construisez avec une révision explicite afin
que le broker puisse la comparer à `expected_policy_revision` :

```bash
opa build --revision 42 -b policy -o bundle.tar.gz

crane append \
  --oci-empty-base \
  --new_layer bundle.tar.gz \
  --new_tag "<registre>/<chemin>/policy:v1.0.0"

# Signez le digest, jamais le tag : un tag peut bouger entre la signature et le pull.
DIGEST="$(crane digest "<registre>/<chemin>/policy:v1.0.0")"
```

## Publier et signer

Seules l'authentification et la forme de la référence changent d'un registre à
l'autre. La commande de signature est partout la même.

### GitHub Container Registry

```bash
echo "$GITHUB_TOKEN" | crane auth login ghcr.io --username "$GITHUB_ACTOR" --password-stdin
REPO="ghcr.io/<org>/<depot>"
```

Dans un workflow, signez en mode keyless et évitez toute gestion de clé. Le job
a besoin de `id-token: write` et `packages: write` :

```yaml
- uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2
  with:
    cosign-release: v3.1.3   # épinglez-la ; la valeur par défaut de l'action n'est pas un contrat
- run: cosign sign --yes "${REPO}@${DIGEST}"
```

Configurez le broker avec l'identité du workflow signataire :

```yaml
cosign:
  certificate_identity_regexp: '^https://github\.com/<org>/<depot>/\.github/workflows/release\.yml@refs/tags/v.*$'
  certificate_oidc_issuer: https://token.actions.githubusercontent.com
```

### Harbor

Utilisez un compte robot limité au projet plutôt qu'un compte utilisateur.

```bash
echo "$HARBOR_ROBOT_SECRET" | crane auth login harbor.example.com \
  --username 'robot$policy-publisher' --password-stdin
REPO="harbor.example.com/<projet>/policy"

cosign sign --key cosign.key --yes "${REPO}@${DIGEST}"
```

Harbor est généralement derrière une autorité de certification privée.
`github-sts` n'a aucune configuration d'autorité de certification : il utilise le
magasin de confiance du système, donc cette autorité doit être installée dans le
conteneur du broker. Sans cela, le téléchargement échoue avec une erreur x509
avant la vérification, et l'échec est comptabilisé comme un échec de
téléchargement et non de signature.

### Sonatype Nexus Repository

Publiez vers un dépôt OCI, pas vers un dépôt Docker historique. L'API Referrers
est arrivée avec le format de dépôt OCI en 3.94.0.

```bash
echo "$NEXUS_PASSWORD" | crane auth login nexus.example.com \
  --username "$NEXUS_USER" --password-stdin
REPO="nexus.example.com/<depot-oci>/policy"

cosign sign --key cosign.key --yes "${REPO}@${DIGEST}"
```

Si le dépôt est servi sur un port autre que celui par défaut, incluez-le dans la
référence : `nexus.example.com:8443/<depot-oci>/policy`.

### JFrog Artifactory

```bash
echo "$ARTIFACTORY_TOKEN" | crane auth login artifactory.example.com \
  --username "$ARTIFACTORY_USER" --password-stdin
REPO="artifactory.example.com/<depot-docker>/policy"

cosign sign --key cosign.key --yes "${REPO}@${DIGEST}"
```

Artifactory nécessite 7.90.1 ou une version ultérieure pour l'API Referrers. Sur
une instance plus ancienne, la signature est écrite via le repli par tag, que
`github-sts` lit toujours.

## Vérifier avant de configurer le broker

Contrôlez d'abord la signature avec cosign, afin qu'un échec de vérification
dans le broker ne soit jamais ambigu entre une mauvaise signature et une
mauvaise configuration :

```bash
cosign verify --key cosign.pub "${REPO}@${DIGEST}"
```

Configurez ensuite le broker sur le même digest immuable :

```yaml
bundles:
  - name: enterprise-baseline
    apps: []
    ref: oci://<registre>/<chemin>/policy@sha256:<digest>
    expected_policy_revision: "42"
    fail_mode: closed
    cosign:
      public_key_ref: /etc/github-sts/cosign.pub
    registry_auth:
      mode: basic
      username: policy-reader
      password_env: REGISTRY_PASSWORD
```

Les identifiants utilisés par le broker doivent pouvoir lister les référents, et
pas seulement récupérer le manifeste. Un compte limité au téléchargement produit
`discovery_failed` plutôt qu'une erreur de signature absente. Voir
[Dépannage]({{< relref "/operations/troubleshooting" >}}) pour le tableau
complet des codes d'erreur.
