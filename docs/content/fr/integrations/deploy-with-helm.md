---
title: Déployer avec Helm
description: "Comment déployer github-sts à l'aide du chart Helm officiel : prérequis, installation sécurisée minimale et vérification opérationnelle."
weight: 1
translationKey: deploy-with-helm
translationStatus: pending-review
---

Le chart [github-sts-helm](https://github.com/Depthmark/github-sts-helm) empaquette github-sts pour Kubernetes.

## Prérequis

- Kubernetes 1.27+
- Helm 3.x
- Une GitHub App avec les permissions configurées
- `cert-manager` (pour TLS) ou un secret TLS existant

## Installation rapide

```bash
helm repo add depthmark https://depthmark.github.io/charts
helm install github-sts depthmark/github-sts \
  --namespace github-sts --create-namespace \
  --set apps.default.appId=123456 \
  --set-file apps.default.privateKey=/path/to/private-key.pem \
  --set oidc.requiredAudience=https://sts.example.com
```

## Installation sécurisée minimale

```yaml
# values.yaml
apps:
  default:
    appId: 123456
    existingSecret: github-sts-keys
    existingSecretKey: default.pem
    orgPolicyRepo: .github
    policyResolution: org_first

oidc:
  allowedIssuers:
    - https://token.actions.githubusercontent.com
  requiredAudience: https://sts.example.com

jti:
  backend: redis
  redisUrl: redis://redis-master:6379/0
  ttl: 1h

resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 5
  targetCPUUtilizationPercentage: 70

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

serviceMonitor:
  enabled: true
  interval: 30s
```

## Vérification

Après l'installation, vérifiez le déploiement :

```bash
# Vérifiez le statut du pod
kubectl get pods -n github-sts

# Vérifiez la préparation
kubectl exec -n github-sts deploy/github-sts -- curl -s localhost:8080/ready

# Vérifiez les métriques
kubectl exec -n github-sts deploy/github-sts -- curl -s localhost:8080/metrics | grep githubsts_ready

# Port-forward pour les tests
kubectl port-forward -n github-sts svc/github-sts 8080:8080

# Échangez un jeton
curl -H "Authorization: Bearer $OIDC_TOKEN" \
  "http://localhost:8080/sts/exchange?scope=myorg/myrepo&app=default&identity=ci"
```

## Référence du chart

Pour la référence complète des valeurs, consultez le [README de github-sts-helm](https://github.com/Depthmark/github-sts-helm) et le `values.yaml` du chart.

> Épinglez toujours une version de chart spécifique (`--version X.Y.Z`) en production. N'utilisez pas `@main` ni un tag flottant.

## Suivant

- [Démarrage rapide de la GitHub Action]({{< relref "/integrations/github-action/quickstart" >}}) : intégrez l'action dans vos workflows
- [De bout en bout sur Kubernetes]({{< relref "/integrations/end-to-end-github-actions-on-kubernetes" >}}): procédure complète
- [Compatibilité]({{< relref "/integrations/compatibility" >}}): combinaisons de composants vérifiées
