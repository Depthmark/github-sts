# Getting Started

This guide walks through running github-sts locally and exchanging your first OIDC token for a scoped GitHub installation token.

## Prerequisites

- **Go 1.26+** (local development) or **Docker** (container builds)
- A [GitHub App](https://docs.github.com/en/apps/creating-github-apps) installed on the org/repos you want to delegate access to
- The GitHub App's **App ID** and **private key** (PEM)
- An OIDC token from a supported issuer (e.g. GitHub Actions, Azure, GCP) — see [OIDC Issuers](oidc-issuers.md)

## 1. Configure credentials

You can supply credentials via environment variables, a YAML config file, or a mix of both.

**Option A — Environment variables:**

```bash
export GITHUBSTS_BUNDLE_ENFORCEMENT="optional"
export GITHUBSTS_APP_DEFAULT_APP_ID="123456"
export GITHUBSTS_APP_DEFAULT_PRIVATE_KEY="$(cat /path/to/private-key.pem)"
export GITHUBSTS_OIDC_ALLOWED_ISSUERS="https://token.actions.githubusercontent.com"
```

This is an explicit local-development posture: with no configured bundles,
authorization is YAML-only and github-sts emits warning, health, metric, and
audit posture signals. Use required mode with a pinned, verified global
baseline for production.

**Option B — YAML config file:**

```bash
export GITHUBSTS_CONFIG_PATH=/path/to/github-sts.yaml
```

The YAML file must contain top-level `bundle_enforcement: required` or
`bundle_enforcement: optional`; omission fails startup. See
[Configuration](configuration.md) for complete required and development
examples.

## 2. Run

### Go

```bash
go build -o github-sts ./cmd/github-sts
./github-sts
```

### Docker

```bash
docker build -t github-sts:local .
docker run -p 8080:8080 \
  -e GITHUBSTS_BUNDLE_ENFORCEMENT \
  -e GITHUBSTS_APP_DEFAULT_APP_ID \
  -e GITHUBSTS_APP_DEFAULT_PRIVATE_KEY \
  -e GITHUBSTS_OIDC_ALLOWED_ISSUERS \
  github-sts:local
```

## 3. Verify

```bash
curl http://localhost:8080/health   # Includes security and bundle posture
curl http://localhost:8080/ready    # {"ready":true}
```

If `/ready` returns `503`, github-sts has not yet completed startup health checks (e.g. GitHub API reachability). Check server logs.

## 4. Write a trust policy

Trust policies live **in the target repository** at `.github/sts/{app}/{identity}.sts.yaml`. For `app=default` and `identity=ci` in `myorg/myrepo`, that's:

```
myorg/myrepo/.github/sts/default/ci.sts.yaml
```

Minimal example for a GitHub Actions workflow on `main`:

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
  pull_requests: write
```

> **Important:** `audience` is mandatory. The same value must be passed to `core.getIDToken(<audience>)` in the workflow that requests the OIDC token. See [Configuration → Trust Policies](configuration.md#trust-policies).

Replace the example IDs with the immutable GitHub owner and repository IDs.
GitHub.com source repositories must opt in to immutable subject claims unless
the server's explicit degraded migration posture is temporarily selected.

## 5. Exchange a token

```bash
curl -H "Authorization: Bearer $OIDC_TOKEN" \
  "http://localhost:8080/sts/exchange?scope=myorg/myrepo&app=default&identity=ci"
```

Expected response:

```json
{
  "token": "ghs_xxxxxxxxxxxxxxxxxxxx",
  "scope": "myorg/myrepo",
  "app": "default",
  "identity": "ci",
  "permissions": {
    "contents": "read",
    "pull_requests": "write"
  }
}
```

The returned `ghs_…` token is a standard GitHub App installation token, scoped
to the resolved target repository ID and the permissions declared in the policy.

## Next steps

- [API Reference](api-reference.md) — full request/response schema, error codes, Go client library
- [Configuration](configuration.md) — every YAML/env var, trust policy schema, and immutable target behavior
- [Deployment](deployment.md) — Docker and Helm
- [Troubleshooting](troubleshooting.md) — common errors and how to fix them
