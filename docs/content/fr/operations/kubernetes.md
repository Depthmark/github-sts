---
title: Kubernetes
description: Sondes, montage de secrets, terminaison TLS et comportement multi-réplicas une fois github-sts en service dans un cluster.
weight: 2
translationKey: kubernetes
translationStatus: pending-review
---

Un chart Helm est maintenu dans le dépôt [github-sts-helm](https://github.com/Depthmark/github-sts-helm). Pour installer le chart, voir [Déployer avec Helm]({{< relref "/integrations/deploy-with-helm" >}}). Cette page couvre le comportement de github-sts une fois en service dans un cluster : sondes, montage de secrets, terminaison TLS et cache multi-réplicas.

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

Le modèle recommandé est de terminer le TLS à l'ingress/Gateway et de conserver le pod en HTTP simple ; voir le bloc `ingress` dans [Déployer avec Helm]({{< relref "/integrations/deploy-with-helm" >}}) pour un exemple complet.

Pour les déploiements exigeant un TLS de bout en bout, github-sts peut également servir HTTPS directement. C'est utile pour les clusters renforcés qui rechiffrent le trafic entre la Gateway et le backend (`BackendTLSPolicy` de Gateway API avec `ServerOnly` ou `ClientAndServer`), ou pour les déploiements autonomes/VM sans ingress. Activez-le via la configuration du serveur :

```yaml
server:
  tls:
    cert_file: /etc/github-sts/tls/tls.crt
    key_file: /etc/github-sts/tls/tls.key
    # client_ca_file: /etc/github-sts/tls/ca.crt   # mTLS optionnel
```

Montez le certificat et la clé depuis un Kubernetes Secret (géré par cert-manager ou un autre émetteur de confiance) :

```yaml
extraVolumes:
  - name: tls
    secret:
      secretName: github-sts-tls

extraVolumeMounts:
  - name: tls
    mountPath: /etc/github-sts/tls
    readOnly: true
```

> **Avertissement : les certificats auto-signés sont réservés au développement local.** Ne déployez jamais un certificat auto-signé en production. Obtenez toujours des certificats auprès d'une CA de confiance (`cert-manager`/Let's Encrypt, une PKI interne ou un service géré). Un certificat auto-signé force chaque client à installer et à faire confiance à votre CA, ce qui est un anti-modèle de sécurité et annule l'objectif d'authentification du TLS.

## Comportement multi-réplicas

L'exécution de plus d'un réplica change le comportement de deux éléments :

- **Cache JTI.** Avec le backend `memory`, chaque réplica a son propre ensemble de rejeu, donc un attaquant qui atteint un autre réplica peut rejouer un jeton OIDC. Utilisez `jti.backend: redis` (voir [Déployer avec Helm]({{< relref "/integrations/deploy-with-helm" >}}) pour les valeurs) pour que chaque instance partage le même ensemble de rejeu.
- **Cache des politiques de confiance.** Par instance, TTL `60s`. Les instances peuvent brièvement servir des politiques différentes après une modification de `.sts.yaml`.
- **Sondes.** Chaque réplica sert son propre point de terminaison `/ready`.

Consultez le dépôt [github-sts-helm](https://github.com/Depthmark/github-sts-helm) pour la référence complète des valeurs.
