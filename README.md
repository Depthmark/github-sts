# github-sts

A Python-based Security Token Service (STS) for the GitHub API.

Workloads with OIDC tokens (GitHub Actions, GCP, AWS, Kubernetes, Okta, …) exchange them for **short-lived, scoped GitHub installation tokens**. No PATs required.

Supports **multiple GitHub Apps** with YAML-based configuration (ideal for Kubernetes ConfigMaps).

Inspired by [**octo-sts/app**](https://github.com/octo-sts/app), an excellent Go-based implementation that pioneered the concept of using OIDC federation for GitHub token exchange.

---

## Why?

Organizations using GitHub often face a dilemma when distributing access:

| Approach | Pros | Cons |
|---|---|---|
| **GitHub App Tokens** | Secure, scoped | Complex to manage across many systems |
| **Personal Access Tokens (PATs)** | Simple | Long-lived, broad permissions |
| **Deploy Keys** | Scoped to repos | Read-only, hard to rotate |
| **SSH Keys** | Familiar | Hard to audit, tied to individuals |

**github-sts** eliminates the tradeoff — workloads present an OIDC token and receive a short-lived, least-privilege GitHub token with no stored credentials.

**CI/CD & Automation:**
```
Workflow → OIDC Token → STS → Scoped GitHub Token → Deploy
```

**Internal Tools & Scripts:**
```
Developer Tool → OIDC Token (from corporate IdP) → STS → Temporary Access
```

---

## How It Works

```
  Workload                  github-sts                   GitHub
     │                          │                          │
     │  GET /sts/exchange       │                          │
     │  ?scope=org/repo         │                          │
     │  &app=my-app             │                          │
     │  &identity=ci            │                          │
     │  Authorization: Bearer   │                          │
     │─────────────────────────>│                          │
     │                          │  Validate OIDC sig/exp   │
     │                          │  Load trust policy       │
     │                          │    {base_path}/{app}/    │
     │                          │    {identity}.sts.yaml   │
     │                          │  Evaluate claims         │
     │                          │  Request install token ──>
     │                          │<─────────────────────────│
     │<─────────────────────────│                          │
     │  { token, permissions }  │                          │
```

---

## Project Structure

```
src/github_sts/              # Main package
  ├── main.py                # FastAPI app entry point
  ├── config.py              # YAML + env var configuration
  ├── policy.py              # Trust policy model & validation
  ├── oidc.py                # OIDC token validation & verification
  ├── github_app.py          # GitHub App token provider
  ├── policy_loader.py       # Policy storage backends
  ├── jti_cache.py           # JTI validation caching
  ├── metrics.py             # Prometheus metrics
  ├── audit.py               # Request auditing
  └── routes/                # API endpoints
      ├── exchange.py        # Token exchange endpoint
      └── health.py          # Health check endpoints

tests/                       # Test suite
  ├── test_policy.py         # Trust policy tests
  ├── test_audit.py          # Audit logging tests
  └── test_jti_cache.py      # JTI cache tests

pyproject.toml              # Project configuration (dependencies, tools)
Dockerfile                  # Multi-stage Docker build
```

---

## Quick Start

### Prerequisites

- Python 3.14+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

### 1. Get GitHub App Credentials

```bash
export PYGITHUBSTS_GITHUB_APP_ID=$(vault kv get -field=github_app_id homelab/github-action/github-sts)
export PYGITHUBSTS_GITHUB_APP_PRIVATE_KEY=$(vault kv get -field=github_app_private_key homelab/github-action/github-sts)
```

Or create a config file (see [config/github-sts.example.yaml](config/github-sts.example.yaml)):
```bash
export PYGITHUBSTS_CONFIG_PATH=./config/github-sts.example.yaml
export PYGITHUBSTS_GITHUB_APP_ID=your_app_id
export PYGITHUBSTS_GITHUB_APP_PRIVATE_KEY=your_private_key
```

### 2. Install Dependencies

**Using uv (recommended):**
```bash
uv sync
```

**Using pip:**
```bash
pip install -e .
```

### 3. Run Locally

**With uv:**
```bash
uv run python -m uvicorn github_sts.main:app --host 0.0.0.0 --port 9999
```

**With pip:**
```bash
python -m uvicorn github_sts.main:app --host 0.0.0.0 --port 9999
```

**With auto-reload (development):**
```bash
uv run python -m uvicorn github_sts.main:app --host 0.0.0.0 --port 9999 --reload
```

### 4. Test the Service

Health check:
```bash
curl http://localhost:9999/health
# {"status":"ok"}
```

Exchange a token:
```bash
curl -H "Authorization: Bearer $OIDC_TOKEN" \
  "http://localhost:9999/sts/exchange?scope=org/repo&app=default&identity=ci"
```

View metrics:
```bash
curl http://localhost:9999/metrics
```

---

## Trust Policies

Policies are fetched directly from GitHub repositories.

Each policy lives at `{base_path}/{app_name}/{identity}.sts.yaml` in the target repository.

Default path: `.github/sts/{app_name}/{identity}.sts.yaml`

For example, with `app=my-app` and `identity=ci`:
`.github/sts/my-app/ci.sts.yaml`

### Policy Schema

**Exact match (most secure):**
```yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:org/repo:ref:refs/heads/main
permissions:
  contents: read
  issues: write
```

**Regex patterns (flexible):**
```yaml
issuer: https://accounts.google.com
subject_pattern: "[0-9]+"         # Google SA unique ID
claim_pattern:
  email: ".*@example\\.com"       # restrict by email domain
permissions:
  contents: read
```

**Restrict to specific workflow (least-privilege):**
```yaml
issuer: https://token.actions.githubusercontent.com
subject_pattern: "repo:org/repo:.*"
claim_pattern:
  job_workflow_ref: "org/repo/.github/workflows/deploy\\.yml@.*"
permissions:
  deployments: write
  statuses: write
```

### Policy Fields

| Field | Type | Description |
|---|---|---|
| `issuer` | string (exact) | OIDC `iss` claim |
| `subject` | string (exact) | OIDC `sub` claim |
| `subject_pattern` | regex | Used when `subject` is absent |
| `claim_pattern` | map[str→regex] | Match any additional JWT claims |
| `permissions` | map[str→read\|write\|admin] | GitHub App permissions to grant |

---

## GitHub Actions Usage

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - name: Get scoped GitHub token
        id: sts
        run: |
          OIDC_TOKEN=$(curl -sH "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=github-sts" | jq -r '.value')

          GITHUB_TOKEN=$(curl -sf \
            -H "Authorization: Bearer $OIDC_TOKEN" \
            "${{ vars.STS_URL }}/sts/exchange?scope=${{ github.repository }}&app=default&identity=ci" \
            | jq -r '.token')

          echo "::add-mask::$GITHUB_TOKEN"
          echo "token=$GITHUB_TOKEN" >> $GITHUB_OUTPUT

      - name: Use scoped token
        env:
          GITHUB_TOKEN: ${{ steps.sts.outputs.token }}
        run: gh issue list
```

---

## Configuration

### Configuration File (YAML)

github-sts uses YAML-based configuration, ideal for Kubernetes ConfigMaps.
See [config/github-sts.example.yaml](config/github-sts.example.yaml) for a complete example.

Set the config file path:
```bash
export PYGITHUBSTS_CONFIG_PATH=/etc/github-sts/config.yaml
```

### Environment Variables

Environment variables with `PYGITHUBSTS_` prefix override YAML config.

**Single-app shortcut (env vars):**
```bash
export PYGITHUBSTS_GITHUB_APP_ID=your_app_id
export PYGITHUBSTS_GITHUB_APP_PRIVATE_KEY=your_private_key
```

**From Vault:**
```bash
export PYGITHUBSTS_GITHUB_APP_ID=$(vault kv get -field=github_app_id homelab/github-action/github-sts)
export PYGITHUBSTS_GITHUB_APP_PRIVATE_KEY=$(vault kv get -field=github_app_private_key homelab/github-action/github-sts)
```

| Env var | Default | Description |
|---|---|---|
| `PYGITHUBSTS_CONFIG_PATH` | — | Path to YAML config file |
| `PYGITHUBSTS_GITHUB_APP_ID` | required | GitHub App numeric ID |
| `PYGITHUBSTS_GITHUB_APP_PRIVATE_KEY` | required | PEM string or path to file |
| `PYGITHUBSTS_GITHUB_APP_NAME` | `default` | App name for env-configured app |
| `PYGITHUBSTS_POLICY_BASE_PATH` | `.github/sts` | Base path in repos for policies |
| `PYGITHUBSTS_POLICY_CACHE_TTL_SECONDS` | `60` | 0 = disable |
| `PYGITHUBSTS_OIDC_ALLOWED_ISSUERS` | — | Comma-sep allowlist (empty = any) |
| `PYGITHUBSTS_JTI_BACKEND` | `memory` | `memory` \| `redis` |
| `PYGITHUBSTS_JTI_REDIS_URL` | — | Redis connection (if backend=redis) |
| `PYGITHUBSTS_AUDIT_FILE_PATH` | `./audit.log` | Audit log file path |
| `PYGITHUBSTS_AUDIT_ROTATION_POLICY` | `daily` | `daily` \| `size` |
| `PYGITHUBSTS_SERVER_LOG_LEVEL` | `INFO` | Log level |
| `PYGITHUBSTS_METRICS_ENABLED` | `true` | Enable/disable metrics |

---

## Metrics

`GET /metrics` — Prometheus text format

| Metric | Type | Description |
|---|---|---|
| `pygithubsts_requests_total` | Counter | HTTP requests by method/path/status |
| `pygithubsts_request_duration_seconds` | Histogram | HTTP latency |
| `pygithubsts_requests_in_flight` | Gauge | Concurrent requests |
| `pygithubsts_token_exchanges_total` | Counter | Exchange attempts by scope/identity/result |
| `pygithubsts_token_exchange_duration_seconds` | Histogram | Exchange latency |
| `pygithubsts_oidc_validation_errors_total` | Counter | OIDC failures by issuer/reason |
| `pygithubsts_policy_loads_total` | Counter | Policy loads by backend/result |
| `pygithubsts_policy_cache_hits_total` | Counter | Cache hits |
| `pygithubsts_policy_cache_misses_total` | Counter | Cache misses |
| `pygithubsts_github_api_calls_total` | Counter | GitHub API calls by endpoint/result |
| `pygithubsts_github_tokens_issued_total` | Counter | Tokens issued by scope/permissions |

---

## Docker

### Build the image

```bash
docker build -t github-sts:latest .
```

### Run with Docker

```bash
docker run -p 9999:8080 \
  -e PYGITHUBSTS_GITHUB_APP_ID="$PYGITHUBSTS_GITHUB_APP_ID" \
  -e PYGITHUBSTS_GITHUB_APP_PRIVATE_KEY="$PYGITHUBSTS_GITHUB_APP_PRIVATE_KEY" \
  github-sts:latest
```

Service will be available at `http://localhost:9999`

---

## Helm Chart

A Helm chart is available for Kubernetes deployments in [`charts/github-sts`](charts/github-sts).

### Basic Deployment

```bash
# Create credentials secret
kubectl create secret generic github-sts-credentials \
  --from-literal=github-app-id="YOUR_GITHUB_APP_ID" \
  --from-file=github-app-private-key=/path/to/private_key.pem

# Install
helm install github-sts ./charts/github-sts \
  --set github.existingSecret="github-sts-credentials"
```

See the [chart README](charts/github-sts/README.md) for full configuration options, Ingress/HTTPRoute setup, and more examples.


## Development

### Linting & Formatting

**Check for linting issues:**
```bash
uv run ruff check .
```

**Format code:**
```bash
uv run ruff format .
```

**Check formatting without applying:**
```bash
uv run ruff format --check .
```

**Check import organization:**
```bash
uv run ruff check --select=I .
```

### Running Tests

**All tests:**
```bash
uv run pytest
```

**Specific test file:**
```bash
uv run pytest tests/test_policy.py -v
```

**Specific test:**
```bash
uv run pytest tests/test_policy.py::TestTrustPolicyExactMatch::test_exact_match_passes -v
```

**With coverage:**
```bash
uv run pytest --cov=src/github_sts
```

### Code Quality Tools

The project uses **Ruff** for linting and formatting:
- **E/W**: pycodestyle (PEP 8)
- **F**: Pyflakes (undefined names, etc.)
- **I**: isort (import organization)
- **C4**: flake8-comprehensions
- **B**: flake8-bugbear (common bugs)
- **UP**: pyupgrade (modern Python syntax)
- **RUF**: Ruff-specific rules

Configuration is in `pyproject.toml` under `[tool.ruff]`

### Using Make (convenience commands)

```bash
make dev       # Install dependencies
make lint      # Run linter
make format    # Format code
make check     # Run all checks
make test      # Run tests
make clean     # Clean cache files
```

---

## Troubleshooting

### "No module named 'src'"
Make sure you've installed the package:
```bash
uv sync
# or
pip install -e .
```

### "ruff: command not found"
Initialize the uv environment:
```bash
uv sync
uv run ruff --version
```

### Tests fail with import errors
Reinstall the package in development mode:
```bash
uv sync
uv run pytest
```

### Health check fails
Verify environment variables are set:
```bash
env | grep PYGITHUBSTS
```

---

## Contributing

We welcome contributions that:
- Improve security
- Enhance usability
- Add observability features
- Extend policy evaluation capabilities
- Improve documentation

---

## License

MIT License — See [LICENSE](LICENSE)

---

## References

- [octo-sts/app](https://github.com/octo-sts/app) — Original Go implementation
- [GitHub OIDC Documentation](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [OpenID Connect Specification](https://openid.net/connect/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [uv Documentation](https://docs.astral.sh/uv/)
- [Ruff Documentation](https://docs.astral.sh/ruff/)
- [pytest Documentation](https://docs.pytest.org/)
- [GitHub App Documentation](https://docs.github.com/en/apps)
