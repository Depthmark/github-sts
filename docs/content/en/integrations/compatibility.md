---
title: Compatibility
description: Supported combinations of github-sts, Helm chart, and Action releases, deprecation windows, and known incompatibilities.
weight: 4
translationKey: compatibility
---

This page documents verified combinations of github-sts, github-sts-helm, and github-sts-action releases.

## Verified combinations

| github-sts | github-sts-helm | github-sts-action | End-to-end test | Status |
|---|---|---|---|---|
| `v0.0.3` | `v0.1.0` | `v0.2.0` | Pending | **Supported** |

Rows marked **Supported** have passed the end-to-end integration test: Helm install, trust policy evaluation, token exchange, and job-end verification.

Rows marked **Pending** are expected to work based on API compatibility but have not been tested together in the latest test run.

## Component compatibility

### github-sts ↔ github-sts-helm

The Helm chart version tracks a compatible github-sts image tag. Check the chart's `appVersion` field in `Chart.yaml`.

### github-sts ↔ github-sts-action

The Action uses the stable `/sts/exchange` API. Minor version bumps may add optional parameters; existing parameters and response shapes remain stable.

## Known incompatibilities

| Issue | Resolution |
|---|---|
| `audience` field mandatory | Every trust policy must declare `audience`; add it and pass the same value to `core.getIDToken()` |
| `immutable_subject` not supported | The field is not in the schema and is ignored if present; use `subject` or `subject_pattern` |
| `repositories` not applied | The field is present but not applied in the exchange flow; use `subject` to scope to a repository |
| Centralized policies are single-repo | A centralized org policy scopes the token to the single repository derived from the OIDC subject |
| Health authentication breaks chart probes | The chart calls `/health` without a Bearer token; leave `health.auth_token` unset on chart-managed deployments |

### Health authentication and the Helm chart

The current `github-sts-helm` chart does not yet support an authenticated
`/health`. Its HTTP liveness probe and its chart test hook call `/health`
without a Bearer token, so enabling health authentication returns `401`,
fails the liveness probe, and fails the test hook. Do not set
`health.auth_token` or `GITHUBSTS_HEALTH_AUTH_TOKEN` on a chart-managed
deployment until a compatible chart release injects the token from a
Kubernetes Secret, switches the liveness probe to TCP, and updates the test
hook. Deployments that provide equivalent custom wiring can enable health
authentication today.

## Deprecation policy

- New required fields receive a one-minor-version deprecation window.
- Removed/renamed fields emit a startup warning for one minor version before removal.
- Security-critical changes (e.g., mandatory `audience`) may have a shorter window, announced in release notes.

## Integration test

The cross-repository integration test performs:

1. Install the released Helm chart on a test cluster
2. Start a configured github-sts instance
3. Run a workflow using the released GitHub Action
4. Verify successful token exchange
5. Verify failed policy authorization (wrong audience)
6. Verify audience mismatch rejection
7. Verify job-end token revocation

Results are published in the [github-sts-helm](https://github.com/Depthmark/github-sts-helm) and [github-sts-action](https://github.com/Depthmark/github-sts-action) repositories.

## Ecosystem links

- **github-sts Helm chart:** <https://github.com/Depthmark/github-sts-helm>
- **github-sts Action documentation:** [GitHub Action]({{< relref "/integrations/github-action" >}}) (published in this site from the action repository)
- **github-sts Action marketplace:** <https://github.com/marketplace/actions/github-sts>
