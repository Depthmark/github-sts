---
title: Architecture
description: Token exchange sequence, authorization pipeline, credential boundaries, policy resolution, caching, and multi-replica behavior.
weight: 1
translationKey: architecture
---

## Security model

```mermaid
flowchart LR
    W["Workload<br/>GitHub Actions / Azure"]

    IDP["OIDC<br/>Identity Provider"]

    subgraph STS["github-sts"]
        V["Verify workload identity"]
        A["Authorize against<br/>trust policy"]
        M["Mint least-privilege<br/>GitHub token"]
        V --> A --> M
    end

    GH["GitHub API"]

    W -- "1. Request OIDC identity" --> IDP
    IDP -- "2. OIDC JWT" --> W

    W -- "3. Exchange OIDC JWT<br/>scope + identity + app" --> V

    A -. "Load trust policy" .-> GH

    A -- "4. Approved scope + perms" --> H["Enterprise Rego<br/>guardrails"]
    H -- "5. All bundles allow" --> M

    M -- "6. GitHub App authentication" --> GH
    GH -- "7. Scoped installation token" --> M

    M -- "8. Short-lived token" --> W
```

**OIDC proves who the workload is → policy determines what it may do → GitHub issues the credential.**

The workload's OIDC token never becomes a GitHub credential. github-sts validates the OIDC identity, authorizes it against a trust policy, then uses its own GitHub App authority to mint a new, independent installation token.

## Token exchange

The full exchange involves two separate GitHub token mints: one to read the trust policy, and one to issue the workload token.

```mermaid
sequenceDiagram
    autonumber

    participant W as Workload
    participant IDP as OIDC Provider
    participant STS as github-sts
    participant GH as GitHub API
    participant P as Trust Policy Repository

    W->>IDP: Request OIDC token
    IDP-->>W: OIDC JWT

    W->>STS: POST /sts/exchange<br/>OIDC JWT + scope + identity + app

    Note over STS: Authenticate workload
    STS->>IDP: OIDC discovery / JWKS (cacheable)
    IDP-->>STS: Signing keys
    STS->>STS: Verify issuer, signature,<br/>expiry, audience and replay

    Note over STS,GH: Authorize requested identity

    STS->>STS: Select configured GitHub App

    opt Policy cache miss
        STS->>STS: Sign GitHub App JWT
        STS->>GH: Mint policy-read installation token<br/>contents: read
        GH-->>STS: Internal installation token

        STS->>P: GET .github/sts/{app}/{identity}.sts.yaml
        P-->>STS: Trust policy
    end

    STS->>STS: Evaluate OIDC claims<br/>against trust policy

    alt Policy denied
        STS-->>W: 403 Forbidden
    else Policy authorized
        STS->>STS: Sign/reuse GitHub App JWT
        STS->>GH: Create installation token<br/>policy permissions + repositories
        GH-->>STS: Scoped installation token
        STS-->>W: Short-lived GitHub token
    end
```

### Credential boundaries

Five distinct credentials exist during an exchange, each with a different holder and purpose:

| Credential | Holder | Purpose |
|---|---|---|
| **OIDC JWT** | Workload → github-sts | Prove workload identity |
| **GitHub App private key** | github-sts only | Sign App JWT (never leaves STS) |
| **GitHub App JWT** | github-sts → GitHub API | Authenticate the GitHub App |
| **Policy-read installation token** | github-sts → GitHub API | Read `.sts.yaml` (contents:read) |
| **Workload installation token** | github-sts → Workload | Authorized GitHub access |

github-sts signs the App JWT using the private key, uses it to authenticate to GitHub, and mints installation tokens. The workload never receives the App JWT, the private key, or the policy-read token.

## Authorization pipeline

Every request passes through these checks, in order. A failure at any step stops the pipeline and returns a `403` with a specific error `code`.

```mermaid
flowchart TD
    A["Exchange request<br/>OIDC JWT + scope + identity + app"]

    B["Validate OIDC JWT<br/>issuer • signature • exp • iat"]
    B2["Validate canonical GitHub identity<br/>immutable owner/repo IDs"]
    C["Validate server audience"]
    D["Reserve JTI<br/>replay protection"]
    E["Resolve GitHub App"]
    E2["Resolve canonical target<br/>owner/repo + immutable IDs"]
    F["Resolve trust policy"]
    G["Validate policy audience"]
    H["Evaluate subject + claims<br/>+ exact source/target IDs"]
    I["Derive repositories<br/>and permissions"]
    R["Evaluate enterprise<br/>Rego bundles"]
    J["Mint installation token"]
    K["Return short-lived token"]

    DENY["Deny request"]
    ERROR["Upstream / internal error"]

    A --> B

    B -->|valid| B2
    B -->|invalid| DENY

    B2 -->|valid| C
    B2 -->|invalid| DENY

    C -->|match| D
    C -->|mismatch| DENY

    D -->|unused| E
    D -->|replayed| DENY

    E -->|configured| E2
    E -->|unknown| DENY

    E2 -->|resolved| F
    E2 -->|not canonical| DENY

    F -->|found| G
    F -->|not found| DENY
    F -->|GitHub error| ERROR

    G -->|match| H
    G -->|mismatch| DENY

    H -->|allowed| I
    H -->|denied| DENY

    I --> R

    R -->|all bundles allow| J
    R -->|any bundle denies| DENY
    R -->|evaluation fault| ERROR

    J -->|created| K
    J -->|GitHub error| ERROR
```

| Step | Check | Error code on failure |
|---|---|---|
| 1 | Parse the JWT and require an `iss` claim | `oidc_invalid` |
| 2 | Issuer allowlist: `iss` in `oidc.allowed_issuers` | `oidc_invalid` |
| 3 | JWKS fetch: retrieve keys from the issuer's pinned `jwks_uri` | `oidc_invalid` |
| 4 | Signature and claims: `kid` matches a JWKS key, RS256 signature valid, `exp` and `iat` required (`nbf` checked when present) | `oidc_invalid` |
| 5 | Canonical GitHub identity: for GitHub.com, cross-check signed owner/repository ID claims and require immutable `sub` format by default | `github_identity_invalid` |
| 6 | Server-wide audience: `aud` matches `oidc.required_audience` (if set) | `audience_mismatch` |
| 7 | JTI replay: `jti` not consumed within the `jti.ttl` window | `replay_detected` |
| 8 | App resolution: `?app=` matches a configured app | `app_unknown` |
| 9 | Target resolution: resolve `scope` to GitHub's current canonical owner/repository names and immutable IDs; organization-level scopes are rejected | `bad_request` |
| 10 | Policy lookup: `.sts.yaml` file found in repo or org policy repo, keyed by target IDs | `policy_not_found` |
| 11 | Policy validation: workload selector, GitHub ID bindings, and `audience:` are present and well-formed | `trust_policy_invalid` |
| 12 | Policy audience: token `aud` matches policy `audience:` | `audience_mismatch` |
| 13 | Claim and relationship evaluation: `subject`/`subject_pattern`, `claim_pattern`, and exact immutable `github.sources[]`/`github.target` IDs match | `policy_denied` |
| 14 | Enterprise Rego enforcement: required mode proves mandatory baseline participation, then composes all applicable app-scoped bundles additively | `org_policy_denied`, `bundle_stale`, `bundle_unavailable`, `bundle_evaluation_failed` |
| 15 | Token mint: GitHub API creates an installation token scoped to the authorized `repository_id` | `upstream_error` |

See [API Reference]({{< relref "/reference/api#error-responses" >}}) for the full error code reference.

## Bundle admission and participation

Startup requires top-level `bundle_enforcement` to be exactly `required` or
`optional`. Required mode admits exactly one global `apps: []` baseline, and
every required-mode bundle must be digest-pinned OCI and cosign verified. The
global baseline is fail-closed and must expose
`data.sts.enterprise.v1.decision` plus `data.sts.enterprise.v1.metadata` with
the v1 contract metadata. The broker requires that baseline to deny malformed
input, missing identity, unknown source, and unknown permission probes before
installation.

At request time, the global baseline applies to every app. App-scoped bundles
can add denials but cannot replace the baseline. Required mode returns
`bundle_unavailable` unless the baseline actually evaluates. Optional mode
with no bundles is deliberately YAML-only and reports that posture through
startup warning, health, metric, and audit signals.

## Policy resolution

For repo-level scope (`scope=org/repo`), policies can live in two places:

- **Repo-local:** `org/repo/.github/sts/{app}/{identity}.sts.yaml`
- **Org-level:** `org/{org_policy_repo}/.github/sts/{app}/{identity}.sts.yaml`

The `policy_resolution` setting per app decides which wins on collision:

```mermaid
flowchart TD
    R["Resolve policy<br/>scope=org/repo"]

    R --> O["Check organization<br/>policy repository"]

    O -->|found| USEORG["Use centralized policy"]
    O -->|not found| LOCAL["Check repository-local policy"]

    LOCAL -->|found| USELOCAL["Use repository policy"]
    LOCAL -->|not found| DENY["Policy not found<br/>Deny"]

    USEORG --> AUTH["Evaluate OIDC claims"]
    USELOCAL --> AUTH
```

The diagram shows `org_first` (default). Other modes:

| Mode | Order | On collision |
|---|---|---|
| `org_first` *(default)* | org → repo fallback | **org wins** |
| `repo_first` *(deprecated)* | repo → org fallback | repo wins |
| `org_only` | org repo only, no fallback | n/a |

If `org_policy_repo` is unset, only the requesting repo is consulted regardless of mode.

## Project structure

```
cmd/github-sts/           Entry point: server bootstrap, signal handling
client/                   Importable Go client library (token exchange + revocation)
internal/
  config/                 YAML + env var configuration
  audit/                  Channel-based async audit logger
  handler/                HTTP handlers (exchange, health, readiness)
  server/                 HTTP server lifecycle, middleware, graceful shutdown
  metrics/                Prometheus metrics registry
  oidc/                   OIDC JWT validation with JWKS caching
  policy/                 Trust policy loading & claim evaluation
  bundle/                 OPA bundle loading, verification, evaluation, and lifecycle
  jti/                    JTI replay cache (in-memory + Redis)
  ratelimit/              Per-identity rate limiting
  github/                 GitHub App auth, installation token provider
config/examples/          Ready-to-use trust policy templates
```

## Caching

| Cache | Default TTL | Setting | Purpose |
|---|---|---|---|
| JWKS keys | `1h` | n/a | Avoid fetching JWKS on every request |
| Target identity | `5m` | n/a | Bound GitHub metadata lookups while refreshing canonical names and immutable IDs |
| Trust policy | `60s` | `GITHUBSTS_POLICY_CACHE_TTL` | Avoid re-fetching `.sts.yaml`; repository targets are isolated by immutable IDs |
| GitHub App installation ID | `15m` | n/a | Avoid re-discovering the installation on every request |
| JTI replay set | `1h` | `GITHUBSTS_JTI_TTL` | Replay window. Use `redis` backend for multi-replica deployments. |

Installation tokens themselves are not cached; each exchange mints a fresh token.

## App pools and failover

A logical app name can be backed by a pool of several physical GitHub Apps (`apps.<name>.instances`) instead of one, so the effective GitHub primary rate-limit ceiling for that app scales with the number of instances. See [Configuration]({{< relref "/reference/configuration#app-pools-multi-instance-rate-limit-rotation" >}}) for the schema. A single-instance app is, internally, a pool of one: every app goes through the same selection path, so there is no separate code path to fall out of sync.

An "instance" here is one physical GitHub App inside one logical app's pool, not a github-sts server replica. The two are unrelated: a pool exists independently of how many github-sts replicas are running, and each replica selects across the same configured pool. See [Multi-replica considerations](#multi-replica-considerations) below for the replica concept.

```mermaid
flowchart TD
    A["Request arrives for app 'checkout'"]
    B["Advance pool cursor,<br/>build ring order"]
    C{"Reachability prober:<br/>any candidate reachable?"}
    D["Filter out instances<br/>reported unreachable"]
    E["Try next candidate<br/>in ring order"]
    F{"Result"}
    G["Return token +<br/>instance label"]
    H{"Error retryable?<br/>(network/5xx/rate-limited)"}
    I["Return error<br/>(no failover)"]
    J{"max_attempts<br/>reached?"}
    K["githubsts_app_pool_exhausted_total++"]

    A --> B --> C
    C -->|yes| D
    C -->|no, all look down| E
    D --> E
    E --> F
    F -->|success| G
    F -->|failure| H
    H -->|no| I
    H -->|yes| J
    J -->|no| E
    J -->|yes| K
```

Per request, `AppPool`:

1. Advances a shared cursor and builds a ring starting from it, so a request's own retries walk consecutive members instead of re-randomizing.
2. Drops any candidate the reachability prober currently reports unreachable, unless that would drop every candidate, in which case it tries the unfiltered ring anyway. A live failure is authoritative; a locally-cached "probably down" is not.
3. Tries candidates in order. On success, returns the token and the serving instance's label. On a retryable failure (network/timeout, 5xx, or a 403 carrying a rate-limit signal), it moves to the next candidate, up to `rotation.max_attempts`. On a non-retryable failure (422 permission/repository mismatch, or any other unclassified error), it returns immediately: a different credential cannot fix a permissions problem.
4. If every tried candidate fails, the request fails and `githubsts_app_pool_exhausted_total` increments. That's the metric worth alerting on, since any single instance's rate-limit gauge dropping doesn't by itself mean requests are failing.

Callers never see which instance served a request; it appears only in the `instance` label on metrics and in the audit log (empty on a failed exchange, since naming one arbitrarily-tried instance out of several that all failed would misleadingly suggest it was uniquely at fault).

The default `rotation.strategy` is `round_robin`, not a rate-limit-aware ranking, deliberately: with R replicas sharing one pool, any single replica's view of an instance's remaining rate limit reflects only the roughly `1/R` slice of traffic it personally routed there, and that blind spot gets worse, not better, as replica count grows. The baseline reachability filter above doesn't have this problem: each replica derives it from its own periodic probe against GitHub's API, not from request traffic, so it stays accurate regardless of replica count. `rate_limit_aware` is accepted as a config value but not yet implemented (github-sts logs a startup warning if it's set); a pool configured with it currently behaves exactly like `round_robin`.

## Multi-replica considerations

- Use `GITHUBSTS_JTI_BACKEND=redis` so JTI replay protection is shared across instances. With `memory`, an attacker who reaches a different replica can replay an OIDC token.
- Trust policy cache is per-instance; instances may briefly serve different policies after a `.sts.yaml` change. Lower `GITHUBSTS_POLICY_CACHE_TTL` if this matters.
- `/ready` returns `503` with `{"ready":false}` while the server is not yet serving and `200` with `{"ready":true}` once it is; use it for load balancer health checks.
- App pool reachability state (used for the baseline liveness filter above) is also per-replica, but unlike the rate-limit-aware strategy, this isn't a meaningful blind spot; see the reasoning above.
