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

The recommended model is to terminate TLS at the ingress/Gateway and keep the pod on plain HTTP. The Gateway API is designed for frontend TLS termination:

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

For deployments that require end-to-end TLS, github-sts can also serve HTTPS directly. This is useful for hardened clusters that re-encrypt Gateway→backend traffic (Gateway API `BackendTLSPolicy` with `ServerOnly` or `ClientAndServer`), or for standalone/VM deployments without an ingress. Enable it via the server configuration:

```yaml
server:
  tls:
    cert_file: /etc/github-sts/tls/tls.crt
    key_file: /etc/github-sts/tls/tls.key
    # client_ca_file: /etc/github-sts/tls/ca.crt   # optional mTLS
```

Mount the certificate and key from a Kubernetes Secret (managed by cert-manager or another trusted issuer):

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

> **Warning — self-signed certificates are for local development only.** Never deploy a self-signed certificate in production. Always obtain certificates from a trusted CA (`cert-manager`/Let's Encrypt, an internal PKI, or a managed service). A self-signed certificate forces every client to install and trust your CA, which is a security anti-pattern and defeats the purpose of TLS authentication.

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
