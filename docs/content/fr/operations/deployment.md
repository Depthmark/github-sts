---
title: Déploiement
description: Déploiement Docker et liste de contrôle de production pour github-sts.
weight: 1
translationKey: deployment
translationStatus: pending-review
---

github-sts peut être déployé avec Docker (cette page) ou avec le chart Helm sur Kubernetes. Pour Kubernetes, voir [Kubernetes]({{< relref "/operations/kubernetes" >}}).

## Docker

L'image officielle est construite à partir d'une base [distroless](https://github.com/GoogleContainerTools/distroless) avec un utilisateur non-root pour une surface d'attaque minimale.

```bash
# Build
docker build -t github-sts:local .

# Run with config file
docker run -p 8080:8080 \
  -v $(pwd)/config/github-sts.example.yaml:/etc/github-sts/config.yaml:ro \
  -e GITHUBSTS_CONFIG_PATH=/etc/github-sts/config.yaml \
  -e GITHUBSTS_APP_DEFAULT_APP_ID="$GITHUBSTS_APP_DEFAULT_APP_ID" \
  -e GITHUBSTS_APP_DEFAULT_PRIVATE_KEY="$GITHUBSTS_APP_DEFAULT_PRIVATE_KEY" \
  github-sts:local

# Run with env vars only
docker run -p 8080:8080 \
  -e GITHUBSTS_CONFIG_PATH=/dev/null \
  -e GITHUBSTS_APP_DEFAULT_APP_ID="$GITHUBSTS_APP_DEFAULT_APP_ID" \
  -e GITHUBSTS_APP_DEFAULT_PRIVATE_KEY="$GITHUBSTS_APP_DEFAULT_PRIVATE_KEY" \
  -e GITHUBSTS_OIDC_ALLOWED_ISSUERS="https://token.actions.githubusercontent.com" \
  -e GITHUBSTS_OIDC_REQUIRED_AUDIENCE="https://sts.example.com" \
  github-sts:local
```

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

> **Avertissement — les certificats auto-signés sont réservés au développement local.** Un certificat auto-signé (généré vous-même avec `openssl`) convient aux tests sur votre machine, mais **ne l'utilisez jamais en production**. En production, les clients rejettent les certificats auto-signés à moins d'installer manuellement leur CA, ce qui est un anti-modèle de sécurité. En production, obtenez des certificats auprès d'une CA de confiance — `cert-manager`/Let's Encrypt, votre PKI interne ou un service géré tel qu'AWS ACM ou Azure Key Vault — et terminez le TLS à l'ingress/Gateway lorsque cela est possible.

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
