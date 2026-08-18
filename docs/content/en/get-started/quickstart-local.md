---
title: Quickstart (local)
translationKey: get-started-quickstart-local
environment: local
weight: 6
---

Already have a GitHub App from [Configure a GitHub App](../configure-github-app/) and
[Install the App](../install-the-app/)? This builds and runs the container image on your own
machine with settings chosen for setup speed, not production use, so you can get the server up
and verified in a few minutes. There is no published github-sts image yet, so this builds one
locally from the repository's `Dockerfile`.

## Prerequisites

- Docker (or another OCI-compatible container runtime)
- A GitHub App you can install on a test organization
- The App's private key as a `.pem` file

## Configuration

{{< snippet "config-local" >}}

## Start the server

{{< snippet "run-local" >}}

## Verify it's running

```bash
curl -s http://127.0.0.1:8080/health
# Includes liveness, security posture, and bundle state
```

Check the logs:

```bash
docker logs github-sts-local
```

With no `GITHUBSTS_JTI_BACKEND` set, the server defaults to the in-memory JTI backend, and the
logs carry a warning on every start: `in-memory JTI cache does not survive restarts and is not
shared across replicas; consider redis for production`. That warning is not noise: replay
protection resets whenever the container restarts.

When you're done, stop and remove the container:

```bash
docker rm -f github-sts-local
```

## Next

This page only gets the server running: it does not exchange a token, because that requires a
real OIDC token from an identity provider, which this quickstart does not mint. See
[Generate a token](../generate-a-token/) for how to request an OIDC token from a GitHub Actions
workflow and exchange it here.

This container also runs with no TLS, no Redis, and no autoscaling; it's for trying github-sts,
not running it. For a real deployment, see [Deploy with Helm](../../integrations/deploy-with-helm/)
and [Kubernetes](../../operations/kubernetes/).
