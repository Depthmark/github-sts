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
export GITHUBSTS_APP_DEFAULT_APP_ID="123456"
export GITHUBSTS_APP_DEFAULT_PRIVATE_KEY="$(cat /path/to/private-key.pem)"
```

**Option B — YAML config file:**

```bash
export GITHUBSTS_CONFIG_PATH=./config/github-sts.example.yaml
```

See [Configuration](configuration.md) for the full reference.

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
  -e GITHUBSTS_APP_DEFAULT_APP_ID \
  -e GITHUBSTS_APP_DEFAULT_PRIVATE_KEY \
  github-sts:local
```

## 3. Verify

```bash
curl http://localhost:8080/health   # {"status":"ok"}
curl http://localhost:8080/ready    # {"status":"ready"}
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
subject: repo:myorg/myrepo:ref:refs/heads/main
audience: https://sts.example.com
permissions:
  contents: read
  pull_requests: write
```

> **Important:** `audience` is mandatory. The same value must be passed to `core.getIDToken(<audience>)` in the workflow that requests the OIDC token. See [Configuration → Trust Policies](configuration.md#trust-policies).

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

The returned `ghs_…` token is a standard GitHub App installation token, scoped to exactly the repositories and permissions declared in the policy.

## Next steps

- [API Reference](api-reference.md) — full request/response schema, error codes, Go client library
- [Configuration](configuration.md) — every YAML/env var, trust policy schema, org-level scope
- [Deployment](deployment.md) — Docker and Helm
- [Troubleshooting](troubleshooting.md) — common errors and how to fix them
