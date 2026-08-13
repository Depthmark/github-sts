---
title: Configuration
description: YAML configuration structure, default values, and complete reference.
weight: 2
translationKey: configuration
---

github-sts is configured through a YAML file, environment variables, or both. Environment variables override values from YAML, making YAML the source of truth for defaults and env vars the right place for secrets and per-environment overrides.

## YAML configuration

Point github-sts at a config file with `GITHUBSTS_CONFIG_PATH`:

```bash
export GITHUBSTS_CONFIG_PATH=/etc/github-sts/config.yaml
```

See [`config/github-sts.example.yaml`](https://github.com/Depthmark/github-sts/blob/main/config/github-sts.example.yaml) in the repo for a complete example.

A minimal config:

```yaml
server:
  port: 8080
  log_level: info

oidc:
  allowed_issuers:
    - https://token.actions.githubusercontent.com
  required_audience: https://sts.example.com

apps:
  default:
    app_id: 123456
    private_key_path: /etc/github-sts/keys/default.pem
    org_policy_repo: .github
    policy_resolution: org_first
```

Valid log levels are lowercase `debug | info | warn | error`. `oidc.allowed_issuers` must contain at least one issuer; an empty list is a validation error.

For production, deploy github-sts with the Helm chart rather than hand-managing this file. See [Deploy with Helm]({{< relref "/integrations/deploy-with-helm" >}}).

## Trust policies

Trust policies are YAML files stored **in the target repository** that define which OIDC identities can request tokens and with what permissions.

**Location:** `.github/sts/{app_name}/{identity}.sts.yaml`

The base path is configurable via `GITHUBSTS_POLICY_BASE_PATH` (default `.github/sts`).

See the [Trust Policies]({{< relref "/learn/trust-policies" >}}) guide for the full policy schema, examples, and security guidance.
