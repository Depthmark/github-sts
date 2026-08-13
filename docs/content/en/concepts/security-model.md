---
title: Security Model
description: Trust boundaries, least privilege, audience binding, replay prevention, explicit subject scoping, logging expectations, and threat model.
weight: 2
translationKey: security-model
---

## Design principles

github-sts is built on five security principles:

### 1. Zero stored credentials

github-sts never stores OIDC tokens, GitHub PATs, or long-lived credentials. The only secret it holds is the GitHub App private key, which is mounted from a secret store (Kubernetes Secret, Vault, cloud KMS).

### 2. Least privilege

Every token exchange is mediated by a **trust policy** that declares exactly what permissions the requesting workload receives. There is no default-deny fallback that grants broad access; if no policy matches, the exchange is rejected.

### 3. Audience binding

Every trust policy must declare an `audience`, and every OIDC token must carry that audience. This prevents cross-RP token reuse: a token minted for another service cannot be redeemed at github-sts.

### 4. Replay prevention

Every OIDC token's `jti` is tracked. If the same `jti` appears twice within the replay window, the second request is rejected. In multi-replica deployments, use Redis to share the JTI cache across instances.

### 5. Explicit subject scoping

Trust policies match the workload identity through `subject` or `subject_pattern` against the OIDC `sub` claim. Prefer an exact `subject` (repository and ref) so the policy's scope is explicit. A broad `subject_pattern` matches any subject, so keep it as narrow as possible.

## Trust boundaries

```
┌─────────────────────────────────────────────────────────┐
│  Workload (CI runner, cloud function, etc.)             │
│  - Holds an OIDC token                                  │
│  - Untrusted: any workload can present any token        │
└──────────────┬──────────────────────────────────────────┘
               │ OIDC JWT (Bearer token)
               ▼
┌─────────────────────────────────────────────────────────┐
│  github-sts                                             │
│  - Validates OIDC signature, expiry, claims             │
│  - Loads and evaluates trust policy                     │
│  - Mints scoped installation token                      │
│  - Trusted: the STS is the policy enforcement point     │
└──────────────┬──────────────────────────────────────────┘
               │ Installation token
               ▼
┌─────────────────────────────────────────────────────────┐
│  GitHub API                                             │
│  - Accepts installation tokens                          │
│  - Trusted: token is cryptographically bound to the App │
└─────────────────────────────────────────────────────────┘
```

## Threat model

### Threats mitigated

| Threat | Mitigation |
|---|---|
| **Token replay** | JTI cache (memory or Redis) rejects duplicate `jti` values |
| **Cross-RP token reuse** | Mandatory `audience` field in every policy + optional `oidc.required_audience` server-wide check |
| **OIDC token forgery** | JWKS validation verifies token signature against the issuer's public keys |
| **Expired token acceptance** | JWT expiry (`exp`) and issued-at (`iat`) are required and validated; `nbf` is checked when present |
| **Issuer spoofing** | `kid` must match a key from the discovered JWKS; JWKS host must be the issuer host or in `trusted_jwks_hosts` |
| **Privilege escalation** | Trust policies define exact permissions per workload; no blanket fallback |
| **Secret exfiltration** | No long-lived secrets stored; private keys mounted read-only from secret stores |
| **Denial of service** | Per-IP rate limiting, bounded request body sizes, and a JWKS cache capped at 100 entries |

### Threats not mitigated

| Threat | Reason | Recommended control |
|---|---|---|
| **GitHub App private key compromise** | If the private key is leaked, an attacker can mint arbitrary tokens | Rotate keys, use short-lived certificates, monitor `githubsts_github_tokens_issued_total` for anomalies |
| **Network eavesdropping** | github-sts listens on plain HTTP | TLS termination at ingress / sidecar |
| **OIDC issuer compromise** | If the issuer is compromised, it can mint valid tokens | Use `allowed_issuers` restrictively; monitor `githubsts_oidc_validation_errors_total` |
| **Redis compromise (JTI backend)** | An attacker with Redis access can clear the JTI cache | Use Redis ACLs, TLS, and network policies |

## Secure deployment checklist

- [ ] `oidc.allowed_issuers` is set to explicit issuer URLs
- [ ] `oidc.required_audience` is set to a deployment-specific value
- [ ] `jti.backend` is `redis` for multi-replica deployments
- [ ] GitHub App private keys are mounted from a secret store, not baked into images
- [ ] `/health` and `/ready` are wired to liveness/readiness probes
- [ ] `/metrics` is scraped by Prometheus
- [ ] Audit log is forwarded to SIEM
- [ ] TLS terminates at ingress/sidecar
- [ ] Rate limits are configured

## Logging and audit

Every token exchange produces a structured audit log entry containing:

- `trace_id`: correlates the response error code to the server-side reason
- `issuer`, `subject`: the OIDC token claims
- `scope`, `app`, `identity`: the exchange parameters
- `jti`: the token's JWT ID
- `result`: `success`, `policy_denied`, `oidc_invalid`, etc.
- `error_reason`: the reason for a rejected exchange
- `duration_ms`: exchange latency
- `user_agent`, `remote_ip`: request metadata

The `trace_id` is returned in the JSON error response so clients can correlate their rejection to the server-side log. The `error` and `code` fields in the response are deliberately generic; the full reason is only in the logs.
