# Configuration

github-sts is configured through a YAML file, environment variables, or both. Environment variables override values from YAML, making YAML the source of truth for defaults and env vars the right place for secrets and per-environment overrides.

## YAML configuration

Point github-sts at a config file with `GITHUBSTS_CONFIG_PATH`:

```bash
export GITHUBSTS_CONFIG_PATH=/etc/github-sts/config.yaml
```

The sections below are the configuration reference; ready-to-use trust-policy
templates live in [`config/examples/`](https://github.com/Depthmark/github-sts/tree/main/config/examples).

A minimal local-development config with YAML-only authorization:

```yaml
bundle_enforcement: optional
bundles: []

server:
  port: 8080
  log_level: INFO

oidc:
  allowed_issuers:
    - https://token.actions.githubusercontent.com
  required_audience: https://sts.example.com
  require_immutable_subject_claims: true

apps:
  default:
    app_id: 123456
    private_key_path: /etc/github-sts/keys/default.pem
    org_policy_repo: .github
    policy_resolution: org_first
```

The explicit optional/no-bundle posture emits a startup warning and observable
health, metric, and audit signals. Production deployments should use required
mode as described under [Enterprise Rego bundles](#enterprise-rego-bundles).

## Environment variables

All variables use the `GITHUBSTS_` prefix. Per-app variables follow `GITHUBSTS_APP_{NAME}_{FIELD}`.

### Server settings

| Variable | Default | Description |
|---|---|---|
| `GITHUBSTS_CONFIG_PATH` | — | Path to YAML config file |
| `GITHUBSTS_PORT` | `8080` | HTTP listen port |
| `GITHUBSTS_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `GITHUBSTS_SUPPRESS_HEALTH_LOGS` | `true` | Suppress health endpoint access logs |
| `GITHUBSTS_METRICS_ENABLED` | `true` | Enable Prometheus metrics |

### GitHub App settings

| Variable | Default | Description |
|---|---|---|
| `GITHUBSTS_APP_{NAME}_APP_ID` | *required* | GitHub App numeric ID |
| `GITHUBSTS_APP_{NAME}_PRIVATE_KEY` | *required* | PEM string (mutually exclusive with `_PATH`) |
| `GITHUBSTS_APP_{NAME}_PRIVATE_KEY_PATH` | — | Path to PEM file |
| `GITHUBSTS_APP_{NAME}_ORG_POLICY_REPO` | — | Central policy repository for repository-scoped requests (e.g. `.github`) |
| `GITHUBSTS_APP_{NAME}_POLICY_RESOLUTION` | `org_first` | `org_first`, `repo_first` (deprecated), or `org_only` |

### Policy & security settings

| Variable | Default | Description |
|---|---|---|
| `GITHUBSTS_POLICY_BASE_PATH` | `.github/sts` | Base path in repos for trust policies |
| `GITHUBSTS_POLICY_CACHE_TTL` | `60s` | Policy cache TTL (`0` to disable) |
| `GITHUBSTS_OIDC_ALLOWED_ISSUERS` | *required* | Comma-separated issuer allowlist. Startup rejects an empty list. |
| `GITHUBSTS_OIDC_REQUIRED_AUDIENCE` | — | Server-wide required `aud` claim. When set, every token must carry this value (defense-in-depth on top of the per-policy `audience:` field). |
| `GITHUBSTS_OIDC_REQUIRE_IMMUTABLE_SUBJECT_CLAIMS` | `true` | Require immutable IDs in GitHub.com `sub`. Exact `false` permits legacy formatting while separate immutable ID claims remain mandatory and emits degraded-posture signals. |
| `GITHUBSTS_BUNDLE_ENFORCEMENT` | *required* | Overrides top-level `bundle_enforcement`. Exact values are `required` or `optional`; omission from both sources fails startup. |
| `GITHUBSTS_JTI_BACKEND` | `memory` | `memory` or `redis` |
| `GITHUBSTS_JTI_REDIS_URL` | — | Redis connection URL (when backend=`redis`) |
| `GITHUBSTS_JTI_TTL` | `1h` | JTI replay protection window |

### Audit settings

| Variable | Default | Description |
|---|---|---|
| `GITHUBSTS_AUDIT_FILE_PATH` | `./audit.log` | Audit log file path |
| `GITHUBSTS_AUDIT_BUFFER_SIZE` | `1024` | Audit channel buffer size |

## Trust policies

Trust policies are YAML files stored **in the target repository** that define which OIDC identities can request tokens and with what permissions.

**Location:** `.github/sts/{app_name}/{identity}.sts.yaml`

For `app=my-app` and `identity=ci`, the path resolves to `.github/sts/my-app/ci.sts.yaml`.

### Policy schema

| Field | Type | Description |
|---|---|---|
| `issuer` | `string` | OIDC `iss` claim (exact match) |
| `subject` | `string` | OIDC `sub` claim (exact match) |
| `subject_pattern` | `regex` | OIDC `sub` claim (regex, used when `subject` is absent) |
| `claim_pattern` | `map[string]regex` | Additional JWT claims to match |
| `audience` | `string` | **Required.** Expected OIDC `aud` claim. A policy without it would accept tokens minted for any other relying party sharing the issuer (cross-RP token reuse) and is rejected at parse time. |
| `github.sources` | `list[{owner_id, repository_id}]` | **Required for GitHub.com.** Exact immutable source repositories allowed to use the policy. |
| `github.target` | `{owner_id, repository_id}` | **Required for GitHub.com.** Exact immutable target repository for the minted token. |
| `permissions` | `map[string]string` | GitHub App permissions (`read` / `write` / `admin`) |

> **`audience` is mandatory.** Every policy must declare the OIDC audience it trusts. The same value must be passed to `core.getIDToken(<audience>)` in the workflow that requests the token. A missing `audience:` is rejected at policy parse time — it would otherwise accept tokens minted for any other relying party that shares the issuer (cross-RP token reuse).

Every policy requires at least one workload selector: `subject`,
`subject_pattern`, or a non-empty `claim_pattern`. GitHub policies should keep
workload selectors focused on context such as `ref` or workflow path; immutable
source and target identity belongs in `github` so repository renames retain the
same authorization.

### Examples

Every `github.sources[]` and `github.target` entry is looked up by numeric
`owner_id` / `repository_id`; see
[OIDC Issuers → Getting the immutable owner and repository IDs](oidc-issuers.md#getting-the-immutable-owner-and-repository-ids)
for how to find those values with the GitHub API before writing the policy
below.

**Repo A → repo A (same repository, exact immutable source and target with a branch selector):**

The most common case: a workflow in a repository requesting a token scoped
back to that same repository. `source` and `target` carry identical
`owner_id`/`repository_id`.

```yaml
issuer: https://token.actions.githubusercontent.com
claim_pattern:
  ref: refs/heads/main
audience: https://sts.example.com
github:
  sources:
    - owner_id: "123456"
      repository_id: "456789"
  target:
    owner_id: "123456"
    repository_id: "456789"
permissions:
  contents: read
  issues: write
```

**Repo A → repo B (cross-repository, same organization):**

This policy file lives **in repo B** (`.github/sts/{app}/{identity}.sts.yaml`
of the target repo) and lists repo A as an allowed source. Same `owner_id` on
both sides means this authorizes purely on the trust policy — no enterprise
bundle exception is required regardless of `bundle_enforcement` posture,
because the `sts.enterprise.v1` baseline's `same_owner` rule allows it
directly. `github.sources[]` accepts multiple entries, so repo B can trust
several source repos at once:

```yaml
# stored at repoB/.github/sts/default/cross-repo-ci.sts.yaml
issuer: https://token.actions.githubusercontent.com
claim_pattern:
  ref: 'refs/heads/.*'
audience: https://sts.example.com
github:
  sources:
    - owner_id: "123456"      # repo A's owner_id (same org as repo B)
      repository_id: "456789" # repo A
  target:
    owner_id: "123456"
    repository_id: "456791"   # repo B
permissions:
  contents: read
  pull_requests: write
```

See [`config/examples/cross-repo-ci.sts.yaml`](https://github.com/Depthmark/github-sts/blob/main/config/examples/cross-repo-ci.sts.yaml)
for a runnable version with two trusted sources.

**Repo A → repo B (cross-organization):**

`owner_id` differs between `source` and `target`, so this is a
cross-organization relationship. The trust policy alone is enough under
`bundle_enforcement: optional` (YAML-only authorization). Under `required`
mode the mandatory `sts.enterprise.v1` baseline's `same_owner` check fails and
the exchange is denied with `rule_id: sts.relationship.cross_org` **unless**
the enterprise bundle's data document also carries a matching, unexpired
`cross_org_exceptions` entry for this exact source/target/app/identity — see
[Enterprise Rego bundles](#enterprise-rego-bundles) below.

```yaml
# stored at repoB/.github/sts/default/deploy.sts.yaml (target: org-b/repo-b)
issuer: https://token.actions.githubusercontent.com
claim_pattern:
  ref: 'refs/heads/.*'
audience: https://sts.example.com
github:
  sources:
    - owner_id: "9001"        # org-a's owner_id (different org)
      repository_id: "9002"   # org-a/repo-a
  target:
    owner_id: "123456"        # org-b's owner_id
    repository_id: "456789"   # org-b/repo-b
permissions:
  contents: read
  deployments: write
  statuses: write
```

Required mode also needs the corresponding enterprise data entry (illustrated
in full under [Enterprise Rego bundles](#enterprise-rego-bundles)):

```json
{
  "exception_id": "xorg-deploy-2026-08",
  "rule_id": "sts.relationship.cross_org",
  "source": {"owner_id": "9001", "repository_id": "9002"},
  "target": {"owner_id": "123456", "repository_id": "456789"},
  "app": "default",
  "identity": "deploy",
  "permission_ceiling": {
    "contents": "read",
    "deployments": "write",
    "statuses": "write"
  },
  "owner": "platform@example.com",
  "approved_by": "security@example.com",
  "reason": "org-a deploy workflow publishes releases into org-b/repo-b",
  "created_at": "2026-08-01T00:00:00Z",
  "expires_at": "2026-08-20T00:00:00Z"
}
```

`owner` and `approved_by` must be distinct identities, `expires_at` must be
within 30 days of `created_at`, and the exception is filtered out once
expired even if the bundle otherwise fails to refresh. The granted
permissions can never exceed `permission_ceiling` here, which itself cannot
exceed the app/target/identity ceilings described under
[Enterprise Rego bundles](#enterprise-rego-bundles).

**Regex patterns (Azure example):**

```yaml
issuer: https://login.microsoftonline.com/{tenant-id}/v2.0
subject_pattern: "[a-f0-9-]+"
claim_pattern:
  azp: "your-azure-app-client-id"
audience: https://sts.example.com
permissions:
  contents: read
```

**Restrict to a specific workflow (least-privilege):**

```yaml
issuer: https://token.actions.githubusercontent.com
audience: https://sts.example.com
claim_pattern:
  job_workflow_ref: "[^/]+/[^/]+/\\.github/workflows/deploy\\.yml@.*"
github:
  sources:
    - owner_id: "123456"
      repository_id: "456789"
  target:
    owner_id: "123456"
    repository_id: "456789"
permissions:
  deployments: write
  statuses: write
```

More ready-to-use templates live in [`config/examples/`](https://github.com/Depthmark/github-sts/tree/main/config/examples).

## Organization-level scope

Organization-level requests (`scope=org`) are currently rejected. Use an exact
repository scope (`scope=org/repo`); the broker resolves the current canonical
name to immutable owner/repository IDs and mints with `repository_ids`.

This fail-closed restriction remains until typed immutable repository sets and
explicit organization-wide grants are covered by mandatory enterprise policy.
`org_policy_repo` may still centralize policy files for repository-scoped
requests; it does not enable organization-wide tokens.

### Resolving identities defined in both repo and org

When the same identity (e.g. `default/ci`) has a policy file in both the requesting repo and the org policy repo, `policy_resolution` decides which one wins:

| Mode | Order | On collision | Use when |
|------|-------|--------------|----------|
| `org_first` *(default)* | org → repo fallback | **org wins** | Org admin owns identity names; repos may self-service identities the org has not claimed. |
| `repo_first` *(deprecated)* | repo → org fallback | repo wins | Backwards-compat only; allows repo owners to override the centralized policy. Emits a deprecation warning at startup. |
| `org_only` | org repo only, no fallback | n/a | Strictly forbid self-service. Repos cannot define their own policies. |

The mode is configured per app:

```yaml
apps:
  default:
    app_id: 123456
    private_key_path: /etc/github-sts/keys/default.pem
    org_policy_repo: .github
    policy_resolution: org_first
```

```bash
export GITHUBSTS_APP_DEFAULT_POLICY_RESOLUTION="org_first"
```

The `org_first` default treats the org policy repo as a **reservation list**: any identity name the org admin writes a file for is reserved org-wide; identities the org has not claimed are delegated to repos. This closes a historical bypass where a repo owner could shadow a centralized policy by dropping a permissive file in their own repo.

If `org_policy_repo` is unset, only the requesting repo is consulted regardless of mode.

## Enterprise Rego bundles

Top-level `bundle_enforcement` is mandatory and accepts exactly `required` or
`optional`. Omission fails startup, including when `bundles` is empty. Set
`GITHUBSTS_BUNDLE_ENFORCEMENT` to override the YAML value.

Enterprise bundles run after the target trust policy allows and before the
GitHub token mint. An evaluated deny wins across the mandatory baseline and all
applicable additive bundles.

### Required production mode

Required mode needs exactly one globally applicable baseline, represented by
`apps: []`. Every configured bundle in required mode must be an OCI reference
pinned exactly to `@sha256:<64 lowercase hex>` and must use cosign keyless or
public-key verification. It must also declare the signed revision expected in
that digest. The global baseline must use `fail_mode: closed`.

```yaml
bundle_enforcement: required

bundles:
  - name: enterprise-baseline
    apps: []
    # Placeholder digest: replace it with the promoted bundle digest.
    ref: oci://ghcr.io/depthmark/github-sts-policy@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    expected_policy_revision: "42"
    poll_interval: 5m
    max_staleness: 10m
    fail_mode: closed
    cosign:
      certificate_identity_regexp: '^https://github\.com/Depthmark/github-sts-policy/\.github/workflows/release\.yml@refs/heads/main$'
      certificate_oidc_issuer: https://token.actions.githubusercontent.com
```

An app-scoped bundle has a nonempty list such as `apps: [release]`. It is
additive: the global baseline still evaluates for that app, and every applicable
bundle must allow. Required-mode pinning and verification rules apply to these
additive bundles too, including `expected_policy_revision`.

`expected_policy_revision` is a quoted positive base-10 `uint64` string. Zero,
signs, whitespace, leading zeroes, non-digits, and overflow are rejected. The
bundle must be built with the same authoritative OPA manifest revision:

```bash
opa build --revision 42 -b policy -o bundle.tar.gz
```

The cosign signature covers the OCI artifact containing `.manifest`. The broker
compares that manifest revision with `expected_policy_revision` before swapping
the runtime snapshot. A mismatch or missing revision fails initial installation;
on reload, the previous engine, digest, and revision remain active.

The mandatory baseline exposes the fixed documents
`data.sts.enterprise.v1.decision` and
`data.sts.enterprise.v1.metadata`. Metadata must be an object with:

- `contract_version: v1`
- `policy_revision` exactly matching the canonical `.manifest.revision`
- A `controls` array containing `immutable_identity` and `permission_boundary`
- An `admission` object containing a known-good `app`, `identity`, exact
  `source` and `target` owner/repository ID pairs, and a nonempty bounded
  `permissions` object

Before installing a baseline candidate, the broker requires the declared
admission context to allow, then independently mutates it for malformed-input,
missing-identity, unknown-source, and unknown-permission probes. Every negative
probe must produce an explicit deny. A missing or malformed fixed document,
invalid metadata, failed probe, pull/signature failure, or compile failure
prevents initial installation; a failed reload leaves the previously admitted
bundle in place.

The exchange input includes canonical `source_identity` and `target_identity`,
the typed `yaml_policy.github` relationship, exact requested permissions,
`requested.repository_ids`, and `requested.organization_wide`. The engine
overwrites `authorization.cross_org_exceptions` with only active records that
passed Go admission; callers and Rego modules cannot add records there.

Cross-org exception admission rejects unknown/missing fields, malformed IDs or
permissions, duplicate contexts, identical owner/approver identities, future
creation, expired records, and lifetimes over 30 days. Expired records are
filtered at evaluation time even if bundle refresh fails.

`cross_org_exceptions` is a field on the enterprise bundle's own data
document (`data.sts.enterprise_config.v1`, built into the OCI bundle
alongside the Rego, not something a caller passes at request time). A full
document — the shape of
[`policies/example_data.json`](https://github.com/Depthmark/github-sts/blob/main/policies/example_data.json)
used by the enterprise baseline's conformance tests — looks like this:

```json
{
  "sts": {
    "enterprise_config": {
      "v1": {
        "contract_version": "v1",
        "approved_source_owner_ids": {"123456": true, "9001": true},
        "approved_target_owner_ids": {"123456": true},
        "apps": {
          "default": {
            "permission_ceiling": {"contents": "write", "deployments": "write", "statuses": "write"},
            "targets": {
              "123456": {
                "repositories": {
                  "456789": {
                    "permission_ceiling": {"contents": "write", "deployments": "write", "statuses": "write"},
                    "identities": {
                      "deploy": {"permission_ceiling": {"contents": "write", "deployments": "write", "statuses": "write"}}
                    }
                  }
                }
              }
            }
          }
        },
        "cross_org_exceptions": [
          {
            "exception_id": "xorg-deploy-2026-08",
            "rule_id": "sts.relationship.cross_org",
            "source": {"owner_id": "9001", "repository_id": "9002"},
            "target": {"owner_id": "123456", "repository_id": "456789"},
            "app": "default",
            "identity": "deploy",
            "permission_ceiling": {"contents": "read", "deployments": "write", "statuses": "write"},
            "owner": "platform@example.com",
            "approved_by": "security@example.com",
            "reason": "org-a deploy workflow publishes releases into org-b/repo-b",
            "created_at": "2026-08-01T00:00:00Z",
            "expires_at": "2026-08-20T00:00:00Z"
          }
        ],
        "org_wide_grants": []
      }
    }
  }
}
```

Every source owner ID and target owner ID that appears anywhere in
`cross_org_exceptions` must also be listed (`true`) in
`approved_source_owner_ids` / `approved_target_owner_ids`, or the enterprise
baseline denies with `sts.context.unknown` before it even reaches the
cross-org rule. `org_wide_grants` must stay an empty array — see
[Organization-level scope](#organization-level-scope): the broker rejects it
non-empty at startup until organization-wide grants are covered by mandatory
enterprise policy. This data document is authored and reviewed by whoever
owns the enterprise policy bundle (typically a platform/security team), built
into the signed OCI bundle, and is the "organization level" of authorization
— individual repo trust policies cannot grant cross-organization access on
their own once `bundle_enforcement: required` is in effect.

### Explicit optional development example

Optional mode does not require enterprise-policy participation. In this
no-bundle development form, exchanges are authorized only by YAML trust
policies:

```yaml
bundle_enforcement: optional
bundles: []
```

Optional mode may use a mutable OCI tag only with an explicit opt-in:

```yaml
bundle_enforcement: optional

bundles:
  - name: local-policy
    apps: []
    ref: oci://localhost:5000/github-sts-policy:dev
    allow_mutable_ref: true
    cosign:
      skip_verification: true
```

`cosign.skip_verification: true` and `file:///...` refs are for optional local
development only and are rejected in required mode. Digest-pinned optional OCI
refs must not set `allow_mutable_ref`; mutable tags must set it to `true`.
Mutable tags are resolved once to a digest before verification and pull so the
verified artifact is the artifact compiled and evaluated.

Optional bundles may omit both `expected_policy_revision` and manifest revision
for legacy development use. If either value is present it must use the canonical
format, and a configured expectation must match the manifest.

### Revision promotion checks

The broker is intentionally stateless and does not persist a highest-seen
revision. Release and deployment CI must compare the candidate against the tuple
from a trusted release or protected base branch. Set `BROKER_VERSION` to a
reviewed broker release or commit:

```bash
go run github.com/depthmark/github-sts/cmd/github-sts-bundle@${BROKER_VERSION} check-promotion \
  --mode=deployment \
  --current-revision="$CURRENT_REVISION" \
  --current-digest="$CURRENT_DIGEST" \
  --candidate-revision="$CANDIDATE_REVISION" \
  --candidate-digest="$CANDIDATE_DIGEST"
```

`release` mode requires a higher revision. `deployment` mode also accepts the
exact same revision/digest tuple as a no-op. Both modes reject a lower revision,
the same revision with different bytes, or one digest claiming two revisions.
Digests passed to this command are raw OCI manifest digests in canonical
`sha256:<64 lowercase hex>` form. Never derive the trusted current tuple from
candidate pull-request content. This command compares supplied tuples; CI must
first verify the candidate signature and confirm that its manifest and rendered
`expected_policy_revision` produce the supplied candidate tuple.

The first policy publication has no prior tuple to compare. Establish revision
`1` through the same protected review and signature process, then require the
comparison for every later release and deployment change.

### Optional posture signals

Optional posture is deliberately visible:

| Signal | Value |
|---|---|
| Startup log | Warning that enterprise bundle enforcement is explicitly optional; reports whether authorization is YAML-only |
| `/health.security` | `bundle_enforcement: optional`, `enterprise_policy_required: false`, and `yaml_only_authorization: true` when no bundle is configured or at least one App lacks bundle coverage |
| `/metrics` | `githubsts_bundle_enforcement_required 0` (`1` in required mode) |
| Exchange audit | `bundle_enforcement: optional` on every event; bundle digest/decisions are absent when no bundle evaluates |
