---
title: Déploiement
description: Déploiement Docker et liste de contrôle de production pour github-sts.
weight: 1
translationKey: deployment
translationStatus: pending-review
---

github-sts peut être déployé avec Docker (cette page) ou avec le chart Helm sur Kubernetes. Pour Kubernetes, voir [Kubernetes]({{< relref "/operations/kubernetes" >}}).

## Docker

L'image officielle est publiée sur
[`ghcr.io/depthmark/github-sts`](https://github.com/Depthmark/github-sts/pkgs/container/github-sts),
construite à partir d'une base [distroless](https://github.com/GoogleContainerTools/distroless) avec un utilisateur non-root pour une surface d'attaque minimale. En production, fixez une version (par exemple `0.0.3`) plutôt que `latest`.

```bash
# Run with config file
docker run -p 8080:8080 \
  -v $(pwd)/config/github-sts.example.yaml:/etc/github-sts/config.yaml:ro \
  -e GITHUBSTS_CONFIG_PATH=/etc/github-sts/config.yaml \
  -e GITHUBSTS_APP_DEFAULT_APP_ID="$GITHUBSTS_APP_DEFAULT_APP_ID" \
  -e GITHUBSTS_APP_DEFAULT_PRIVATE_KEY="$GITHUBSTS_APP_DEFAULT_PRIVATE_KEY" \
  ghcr.io/depthmark/github-sts:0.0.3

# Run with env vars only
docker run -p 8080:8080 \
  -e GITHUBSTS_CONFIG_PATH=/dev/null \
  -e GITHUBSTS_APP_DEFAULT_APP_ID="$GITHUBSTS_APP_DEFAULT_APP_ID" \
  -e GITHUBSTS_APP_DEFAULT_PRIVATE_KEY="$GITHUBSTS_APP_DEFAULT_PRIVATE_KEY" \
  -e GITHUBSTS_OIDC_ALLOWED_ISSUERS="https://token.actions.githubusercontent.com" \
  -e GITHUBSTS_OIDC_REQUIRED_AUDIENCE="https://sts.example.com" \
  ghcr.io/depthmark/github-sts:0.0.3
```

Pour construire depuis les sources : `docker build -t github-sts:local .` à la racine du dépôt, puis remplacez le nom d'image ci-dessus.

## Binaires précompilés {#prebuilt-binaries}

Chaque version publie également des archives `tar.gz` du serveur pour Linux et
macOS sur `amd64` et `arm64`, attachées à la
[version GitHub](https://github.com/Depthmark/github-sts/releases).

Docker reste la méthode recommandée pour exécuter le serveur. Utilisez un
binaire lorsqu'aucun environnement d'exécution de conteneurs n'est disponible,
ou lorsque vous souhaitez exécuter le serveur directement sur un hôte.

Les archives contiennent uniquement le serveur, ce qui correspond à l'image de
conteneur. Le contrôle de révision `github-sts-bundle` est un outil de
construction plutôt qu'un composant déployé : il s'exécute directement depuis le
module à une version fixée, comme décrit sous « Revision promotion checks » dans
[Configuration]({{< relref "/reference/configuration" >}}).

```bash
curl -sSLO "https://github.com/Depthmark/github-sts/releases/latest/download/github-sts_Linux_x86_64.tar.gz"
tar xzf github-sts_Linux_x86_64.tar.gz github-sts
```

Pour fixer une version plutôt que suivre la plus récente, remplacez
`latest/download` par `download/v<version>`. Les versions antérieures ne
publient que l'image de conteneur.

Le serveur n'accepte aucune option en ligne de commande. Il lit sa configuration
depuis `GITHUBSTS_CONFIG_PATH` et les variables d'environnement `GITHUBSTS_*`,
exactement comme les exemples Docker ci-dessus, et se termine sur une erreur de
validation lorsqu'un paramètre requis est absent. Voir
[Configuration]({{< relref "/reference/configuration" >}}).

### Vérifier une archive téléchargée {#verifying-a-downloaded-archive}

Chaque version porte deux garanties indépendantes de chaîne
d'approvisionnement, et aucune des deux n'est vérifiée pour vous. Vérifiez les
deux avant d'exécuter un binaire issu d'une version.

Vous avez besoin de [cosign](https://github.com/sigstore/cosign) v3 ou
ultérieur et de la ligne de commande GitHub, authentifiée avec `gh auth login`.
Sur macOS, utilisez `shasum -a 256` à la place de `sha256sum` : il n'a pas
d'équivalent à `--ignore-missing`, vérifiez donc une archive par son nom plutôt
que la liste entière.

La première garantie est une signature cosign sur `checksums.txt`. La
publication s'exécute dans un workflow réutilisable partagé, donc l'identité de
signature est ce workflow dans `Depthmark/reusable-workflows`, et non ce dépôt.
Vérifiez la liste d'empreintes, puis l'archive par rapport à cette liste :

```bash
BASE="https://github.com/Depthmark/github-sts/releases/latest/download"
curl -sSLO "${BASE}/checksums.txt"
curl -sSLO "${BASE}/checksums.txt.sigstore.json"

cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/Depthmark/reusable-workflows/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt

sha256sum --ignore-missing --check checksums.txt
```

`cosign verify-blob` affiche `Verified OK` et se termine avec le code zéro en
cas de succès. Les deux options de certificat sont obligatoires pour la
vérification sans clé : cosign refuse de s'exécuter sans contrainte d'identité,
il n'y a donc aucun succès silencieux à craindre. Le risque réel est d'élargir
le motif, ce qui accepte les signatures d'autres workflows.

La seconde garantie est une attestation de provenance SLSA couvrant tous les
artefacts listés dans ce fichier d'empreintes. Elle enregistre quel workflow, à
quel commit, a produit l'archive :

```bash
gh attestation verify github-sts_Linux_x86_64.tar.gz \
  --repo Depthmark/github-sts \
  --signer-workflow Depthmark/reusable-workflows/.github/workflows/go-release.yml
```

`--repo` est obligatoire. C'est `--signer-workflow` qui rattache l'attestation
au workflow de publication : sans cette option, le contrôle réussit encore pour
n'importe quel workflow de `Depthmark/github-sts`, ce qui est une garantie plus
faible que celle recherchée. La commande se termine avec un code non nul
lorsqu'aucune attestation ne correspond.

L'image de conteneur porte sa propre signature et sa propre provenance,
produites par un autre workflow réutilisable, elle se vérifie donc avec une
identité de signature différente. L'exécution de publication affiche les
commandes pour l'image dans son résumé de tâche.

## TLS et mTLS

github-sts prend en charge HTTPS et le mTLS nativement, mais ne gère pas les certificats. Le TLS est activé implicitement lorsqu'un certificat et une clé sont fournis ; ajoutez un bundle de CA clientes pour exiger les certificats clients.

```yaml
server:
  host: "0.0.0.0"
  port: 8443
  tls:
    cert_file: /etc/github-sts/tls/tls.crt
    key_file: /etc/github-sts/tls/tls.key
    # client_ca_file: /etc/github-sts/tls/ca.crt   # mTLS optionnel
```

Lancez-le en montant le certificat et la clé en lecture seule (le conteneur s'exécute en tant qu'utilisateur non-root, les fichiers doivent donc être lisibles par celui-ci) :

```bash
docker run -p 8443:8443 \
  -v $(pwd)/config/github-sts.example.yaml:/etc/github-sts/config.yaml:ro \
  -v $(pwd)/certs:/etc/github-sts/tls:ro \
  -e GITHUBSTS_CONFIG_PATH=/etc/github-sts/config.yaml \
  github-sts:local
```

Vérifiez :

```bash
curl --cacert certs/ca.crt https://localhost:8443/health
```

> **Avertissement : les certificats auto-signés sont réservés au développement local.** Un certificat auto-signé (généré vous-même avec `openssl`) convient aux tests sur votre machine, mais **ne l'utilisez jamais en production**. En production, les clients rejettent les certificats auto-signés à moins d'installer manuellement leur CA, ce qui est un anti-modèle de sécurité. En production, obtenez des certificats auprès d'une CA de confiance (`cert-manager`/Let's Encrypt, votre PKI interne ou un service géré tel qu'AWS ACM ou Azure Key Vault) et terminez le TLS à l'ingress/Gateway lorsque cela est possible.

Pour les déploiements autonomes nécessitant le mTLS, ajoutez le bundle de CA clientes et exigez que les clients présentent un certificat signé par celle-ci. Consultez [Configuration]({{< relref "/reference/configuration" >}}) pour la référence TLS complète.

## Liste de contrôle de production

Avant d'exposer github-sts publiquement :

- [ ] `oidc.allowed_issuers` est défini avec la liste explicite des émetteurs que vous acceptez.
- [ ] `oidc.required_audience` est défini avec une valeur unique à ce déploiement STS (par ex. `https://sts.example.com`). Le champ `audience:` de chaque politique de confiance lui correspond.
- [ ] `jti.backend` est `redis` si vous exécutez plus d'un réplica.
- [ ] Les clés privées de la GitHub App sont montées depuis un magasin de secrets (Kubernetes Secret, Vault, cloud KMS), **pas** intégrées aux images ni aux fichiers d'environnement.
- [ ] `/health` et `/ready` sont reliés aux sondes de vivacité/préparation.
- [ ] `/metrics` est collecté par Prometheus et les tableaux de bord sont en place.
- [ ] Le journal d'audit est écrit dans un emplacement persistant et transmis à votre SIEM.
- [ ] Le TLS se termine à l'ingress/Gateway, ou le TLS/mTLS natif est activé avec des certificats **émis par une CA** (jamais auto-signés en production).
- [ ] Les limites de débit et de taille de requête sont configurées au niveau de l'ingress.
