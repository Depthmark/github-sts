---
title: Kubernetes
description: Helm installation, probes, secret mounting, TLS termination, Redis setup, and multi-replica behavior.
weight: 2
translationKey: kubernetes
---

A Helm chart is maintained in the [github-sts-helm](https://github.com/Depthmark/github-sts-helm) repository.

## Installation

```bash
helm repo add depthmark https://depthmark.github.io/charts
helm install github-sts depthmark/github-sts \
  --namespace github-sts --create-namespace \
  --set apps.default.appId=123456 \
  --set-file apps.default.privateKey=/path/to/private-key.pem \
  --set oidc.requiredAudience=https://sts.example.com
```

## Probes

| Probe | Endpoint | Success | Failure |
|---|---|---|---|
| Liveness | `/health` | `200` `{"status":"ok"}` | — |
| Readiness | `/ready` | `200` `{"ready":true}` | `503` `{"ready":false}` |

`/ready` returns `200` with `{"ready":true}` once the server is serving and `503` with `{"ready":false}` while it is not. Use it for Kubernetes readiness probes and load balancer health checks.

## Secret mounting

Mount GitHub App private keys from Kubernetes Secrets:

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

## TLS termination

github-sts listens on plain HTTP. Terminate TLS at the ingress or service mesh:

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

## Redis for multi-replica JTI

When running more than one replica, use Redis for shared JTI replay protection:

```yaml
jti:
  backend: redis
  redisUrl: redis://redis-master:6379/0
  ttl: 1h
```

With the `memory` backend, an attacker who reaches a different replica can replay an OIDC token.

## Multi-replica behavior

- **JTI cache:** Use Redis (see above). Each instance shares the replay set.
- **Trust policy cache:** Per-instance, TTL `60s`. Instances may briefly serve different policies after a `.sts.yaml` change.
- **Probes:** Each replica serves its own `/ready` endpoint.

See the [github-sts-helm](https://github.com/Depthmark/github-sts-helm) repository for the complete values reference and installation options.
