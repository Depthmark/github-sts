---
title: Kubernetes
description: Installation Helm, sondes, montage de secrets, terminaison TLS, configuration Redis et comportement multi-réplicas.
weight: 2
translationKey: kubernetes
translationStatus: pending-review
---

Un chart Helm est maintenu dans le dépôt [github-sts-helm](https://github.com/Depthmark/github-sts-helm).

## Installation

```bash
helm repo add depthmark https://depthmark.github.io/charts
helm install github-sts depthmark/github-sts \
  --namespace github-sts --create-namespace \
  --set apps.default.appId=123456 \
  --set-file apps.default.privateKey=/path/to/private-key.pem \
  --set oidc.requiredAudience=https://sts.example.com
```

## Sondes

| Sonde | Point de terminaison | Succès | Échec |
|---|---|---|---|
| Vivacité | `/health` | `200` `{"status":"ok"}` | — |
| Préparation | `/ready` | `200` `{"ready":true}` | `503` `{"ready":false}` |

`/ready` renvoie `200` avec `{"ready":true}` une fois que le serveur est en service et `503` avec `{"ready":false}` tant qu'il ne l'est pas. Utilisez-le pour les sondes de préparation Kubernetes et les vérifications de santé des équilibreurs de charge.

## Montage de secrets

Montez les clés privées de la GitHub App depuis des Kubernetes Secrets :

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: github-sts-keys
type: Opaque
stringData:
  default.pem: |
    -----BEGIN RSA PRIVATE KEY-----
    ...
    -----END RSA PRIVATE KEY-----
```

```yaml
# In your values override:
apps:
  default:
    appId: 123456
    privateKeyPath: /etc/github-sts/keys/default.pem
    orgPolicyRepo: .github

extraVolumes:
  - name: keys
    secret:
      secretName: github-sts-keys

extraVolumeMounts:
  - name: keys
    mountPath: /etc/github-sts/keys
    readOnly: true
```

## Terminaison TLS

github-sts écoute sur HTTP simple. Terminez le TLS au niveau de l'ingress ou du service mesh :

```yaml
ingress:
  enabled: true
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: sts.example.com
      paths:
        - path: /
  tls:
    - secretName: sts-tls
      hosts:
        - sts.example.com
```

## Redis pour le JTI multi-réplicas

Lorsque vous exécutez plus d'un réplica, utilisez Redis pour la protection partagée contre le rejeu JTI :

```yaml
jti:
  backend: redis
  redisUrl: redis://redis-master:6379/0
  ttl: 1h
```

Avec le backend `memory`, un attaquant qui atteint un autre réplica peut rejouer un jeton OIDC.

## Comportement multi-réplicas

- **Cache JTI :** Utilisez Redis (voir ci-dessus). Chaque instance partage l'ensemble de rejeu.
- **Cache des politiques de confiance :** Par instance, TTL `60s`. Les instances peuvent brièvement servir des politiques différentes après une modification de `.sts.yaml`.
- **Sondes :** Chaque réplica sert son propre point de terminaison `/ready`.

Consultez le dépôt [github-sts-helm](https://github.com/Depthmark/github-sts-helm) pour la référence complète des valeurs et les options d'installation.
