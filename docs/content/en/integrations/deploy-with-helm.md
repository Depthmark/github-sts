---
title: Deploy with Helm
description: "How to deploy github-sts using the official Helm chart: prerequisites, minimal secure installation, and operational verification."
weight: 1
translationKey: deploy-with-helm
---

The [github-sts-helm](https://github.com/Depthmark/github-sts-helm) chart packages github-sts for Kubernetes.

## Prerequisites

- Kubernetes 1.27+
- Helm 3.x
- A GitHub App with permissions configured
- `cert-manager` (for TLS) or an existing TLS secret

## Quick install

```bash
helm repo add depthmark https://depthmark.github.io/charts
helm install github-sts depthmark/github-sts \
  --namespace github-sts --create-namespace \
  --set apps.default.appId=123456 \
  --set-file apps.default.privateKey=/path/to/private-key.pem \
  --set oidc.requiredAudience=https://sts.example.com
```

## Minimal secure installation

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
    - https://accounts.google.com
  requiredAudience: https://sts.example.com
  trustedJwksHosts:
    https://accounts.google.com:
      - www.googleapis.com

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

## Verification

After installation, verify the deployment:

```bash
# Check pod status
kubectl get pods -n github-sts

# Check readiness
kubectl exec -n github-sts deploy/github-sts -- curl -s localhost:8080/ready

# Check metrics
kubectl exec -n github-sts deploy/github-sts -- curl -s localhost:8080/metrics | grep githubsts_ready

# Port-forward for testing
kubectl port-forward -n github-sts svc/github-sts 8080:8080

# Exchange a token
curl -H "Authorization: Bearer $OIDC_TOKEN" \
  "http://localhost:8080/sts/exchange?scope=myorg/myrepo&app=default&identity=ci"
```

## Chart reference

For the complete values reference, see the [github-sts-helm README](https://github.com/Depthmark/github-sts-helm) and the chart's `values.yaml`.

> Always pin to a specific chart version (`--version X.Y.Z`) in production. Do not use `@main` or a floating tag.

## Next

- [Use the GitHub Action]({{< relref "/integrations/use-github-action" >}}): integrate the action in your workflows
- [End-to-End on Kubernetes]({{< relref "/integrations/end-to-end-github-actions-on-kubernetes" >}}): complete walkthrough
- [Compatibility]({{< relref "/integrations/compatibility" >}}): verified component combinations
