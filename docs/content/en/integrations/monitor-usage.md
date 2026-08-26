---
title: Monitor usage
description: Watch Prometheus metrics and read the structured audit log to confirm what github-sts actually issued.
weight: 5
translationKey: monitor-usage
---

A trust policy declares what's *allowed*. Metrics and the audit log show what actually happened.
The gap between the two is where you'll catch a misconfigured policy or a compromised identity.

## Prometheus metrics

Every exchange is counted at `GET /metrics`. The two to watch first:

```promql
# Exchange attempts by app, scope, identity, issuer, result
githubsts_token_exchanges_total

# JTI replay attempts: investigate immediately, this means a token was reused
rate(githubsts_jti_replay_attempts_total[5m]) > 0
```

See [Metrics](../../reference/metrics/) for the complete list: HTTP, exchange, JTI, policy,
GitHub API, and reachability metrics, plus recommended alert queries.

## Audit log

Every token exchange produces a structured audit log entry:

| Field | Meaning |
|---|---|
| `trace_id` | Correlates a response error code to the server-side reason |
| `issuer`, `subject` | The OIDC token claims presented |
| `scope`, `app`, `identity` | The exchange parameters requested |
| `jti` | The token's JWT ID |
| `result` | `success`, `policy_denied`, `oidc_invalid`, etc. |
| `error_reason` | Why a rejected exchange was rejected |
| `duration_ms` | Exchange latency |

Grep `result!=success` to find denied or invalid attempts; a spike is either a broken workflow or
someone probing your policies.

## Next

You've covered the full kickstart. From here:

- [OIDC Issuers](../../oidc-issuers/): configure additional identity providers
- [Policy Recipes](../../concepts/policy-recipes/): copy-and-paste trust policy patterns
- [Helm Chart]({{< relref "/integrations/helm-chart" >}}): run github-sts in Kubernetes for real workloads
- [Kubernetes](../../operations/kubernetes/): probes, secret mounting, TLS, and multi-replica behavior
