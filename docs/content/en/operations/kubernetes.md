---
title: Kubernetes
description: Probes, secret mounting, TLS termination, and multi-replica behavior once github-sts is running in a cluster.
weight: 2
translationKey: kubernetes
---

A Helm chart is maintained in the [github-sts-helm](https://github.com/Depthmark/github-sts-helm) repository. For installing the chart, see [Helm chart installation]({{< relref "/integrations/helm-chart/installation" >}}). This page covers how github-sts behaves once it is running in a cluster: probes, secret mounting, TLS termination, and multi-replica caching.

## Probes

| Probe | Endpoint | Success | Failure |
|---|---|---|---|
| Liveness | `/health` | `200` with liveness and diagnostic state | `401` when health authentication is configured and the Bearer token is missing or incorrect |
| Readiness | `/ready` | `200` `{"ready":true}` | `503` `{"ready":false}` |

`/ready` returns `200` with `{"ready":true}` once the server is serving and `503` with `{"ready":false}` while it is not. Use it for Kubernetes readiness probes and load balancer health checks.

The current `github-sts-helm` chart uses an unauthenticated HTTP `/health`
liveness probe. Do not enable health authentication with that probe. A
compatible deployment must inject `GITHUBSTS_HEALTH_AUTH_TOKEN` from a
Kubernetes Secret and use a TCP liveness probe, or provide equivalent custom
wiring. See [Compatibility]({{< relref "/integrations/compatibility" >}}) for
the chart test-hook limitation.

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

The recommended model is to terminate TLS at the ingress/Gateway and keep the pod on plain HTTP; see the `ingress` block in [Networking]({{< relref "/integrations/helm-chart/networking" >}}) for a working example.

For deployments that require end-to-end TLS, github-sts can also serve HTTPS directly. This is useful for hardened clusters that re-encrypt Gateway to backend traffic (Gateway API `BackendTLSPolicy` with `ServerOnly` or `ClientAndServer`), or for standalone/VM deployments without an ingress. Enable it via the server configuration:

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

> **Warning: self-signed certificates are for local development only.** Never deploy a self-signed certificate in production. Always obtain certificates from a trusted CA (`cert-manager`/Let's Encrypt, an internal PKI, or a managed service). A self-signed certificate forces every client to install and trust your CA, which is a security anti-pattern and defeats the purpose of TLS authentication.

## Multi-replica behavior

Running more than one replica changes how two things behave:

- **JTI cache.** With the `memory` backend, each replica has its own replay set, so an attacker who reaches a different replica can replay an OIDC token. Use `jti.backend: redis` (see the [Values Reference]({{< relref "/integrations/helm-chart/values" >}})) so every instance shares the same replay set.
- **Trust policy cache.** Per-instance, TTL `60s`. Instances may briefly serve different policies after a `.sts.yaml` change.
- **Probes.** Each replica serves its own `/ready` endpoint.

See the [github-sts-helm](https://github.com/Depthmark/github-sts-helm) repository for the complete values reference.
