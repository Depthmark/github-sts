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

## Liste de contrôle de production

Avant d'exposer github-sts publiquement :

- [ ] `oidc.allowed_issuers` est défini avec la liste explicite des émetteurs que vous acceptez.
- [ ] `oidc.required_audience` est défini avec une valeur unique à ce déploiement STS (par ex. `https://sts.example.com`). Le champ `audience:` de chaque politique de confiance lui correspond.
- [ ] `jti.backend` est `redis` si vous exécutez plus d'un réplica.
- [ ] Les clés privées de la GitHub App sont montées depuis un magasin de secrets (Kubernetes Secret, Vault, cloud KMS), **pas** intégrées aux images ni aux fichiers d'environnement.
- [ ] `/health` et `/ready` sont reliés aux sondes de vivacité/préparation.
- [ ] `/metrics` est collecté par Prometheus et les tableaux de bord sont en place.
- [ ] Le journal d'audit est écrit dans un emplacement persistant et transmis à votre SIEM.
- [ ] Le TLS se termine à l'ingress/sidecar: github-sts lui-même écoute sur HTTP simple.
- [ ] Les limites de débit et de taille de requête sont configurées au niveau de l'ingress.
