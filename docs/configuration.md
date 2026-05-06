# Configuration

github-sts is configured through a YAML file, environment variables, or both. Environment variables override values from YAML, making YAML the source of truth for defaults and env vars the right place for secrets and per-environment overrides.

## YAML configuration

Point github-sts at a config file with `GITHUBSTS_CONFIG_PATH`:

```bash
export GITHUBSTS_CONFIG_PATH=/etc/github-sts/config.yaml
```

See [`config/github-sts.example.yaml`](https://github.com/Depthmark/github-sts/blob/main/config/github-sts.example.yaml) in the repo for a complete example.

A minimal config:

```yaml
port: 8080
log_level: INFO

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
| `GITHUBSTS_APP_{NAME}_ORG_POLICY_REPO` | — | Repo for org-level policies (e.g. `.github`) |
| `GITHUBSTS_APP_{NAME}_POLICY_RESOLUTION` | `org_first` | `org_first`, `repo_first` (deprecated), or `org_only` |

### Policy & security settings

| Variable | Default | Description |
|---|---|---|
| `GITHUBSTS_POLICY_BASE_PATH` | `.github/sts` | Base path in repos for trust policies |
| `GITHUBSTS_POLICY_CACHE_TTL` | `60s` | Policy cache TTL (`0` to disable) |
| `GITHUBSTS_OIDC_ALLOWED_ISSUERS` | — | Comma-separated issuer allowlist (empty = any) |
| `GITHUBSTS_OIDC_REQUIRED_AUDIENCE` | — | Server-wide required `aud` claim. When set, every token must carry this value (defense-in-depth on top of the per-policy `audience:` field). |
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
| `repositories` | `list[string]` | Restrict org-scoped tokens to specific repos |
| `permissions` | `map[string]string` | GitHub App permissions (`read` / `write` / `admin`) |

> **`audience` is mandatory.** Every policy must declare the OIDC audience it trusts. The same value must be passed to `core.getIDToken(<audience>)` in the workflow that requests the token. A missing `audience:` is rejected at policy parse time — it would otherwise accept tokens minted for any other relying party that shares the issuer (cross-RP token reuse).

### Examples

**Exact match (most secure):**

```yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:org/repo:ref:refs/heads/main
audience: https://sts.example.com
permissions:
  contents: read
  issues: write
```

**Regex patterns (Azure example):**

```yaml
issuer: https://login.microsoftonline.com/{tenant-id}/v2.0
subject_pattern: "[a-f0-9-]+"
claim_pattern:
  azp: "your-azure-app-client-id"
permissions:
  contents: read
```

**Restrict to a specific workflow (least-privilege):**

```yaml
issuer: https://token.actions.githubusercontent.com
subject_pattern: "repo:org/repo:.*"
audience: https://sts.example.com
claim_pattern:
  job_workflow_ref: "org/repo/.github/workflows/deploy\\.yml@.*"
permissions:
  deployments: write
  statuses: write
```

More ready-to-use templates live in [`config/examples/`](https://github.com/Depthmark/github-sts/tree/main/config/examples).

## Organization-level scope

In addition to repo-level scope (`scope=org/repo`), github-sts supports **org-level scope** (`scope=myorg`):

- **Org-wide tokens** — permissions across all repositories
- **Repo-restricted org tokens** — scope to a subset via the `repositories` field
- **Org-level permissions** — `organization_administration`, `members`, etc.

Configure `org_policy_repo` to specify where org-level policies live:

```yaml
apps:
  default:
    app_id: 123456
    private_key_path: /etc/github-sts/keys/default.pem
    org_policy_repo: .github
```

```bash
export GITHUBSTS_APP_DEFAULT_ORG_POLICY_REPO=".github"
```

**Org-level policy example** (placed in `myorg/.github/.github/sts/default/org-ci.sts.yaml`):

```yaml
issuer: https://token.actions.githubusercontent.com
subject_pattern: "repo:myorg/.*"
audience: https://sts.example.com
repositories:
  - frontend
  - backend
  - shared-libs
permissions:
  contents: read
  pull_requests: write
```

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
