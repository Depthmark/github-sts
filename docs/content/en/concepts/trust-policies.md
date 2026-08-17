---
title: Trust Policies
description: Understand trust policy concepts, field definitions, and safe examples.
weight: 3
translationKey: trust-policies
---

Trust policies are YAML files stored **in the target repository** that define which OIDC identities can request tokens and with what permissions.

**Location:** `.github/sts/{app_name}/{identity}.sts.yaml`

For `app=my-app` and `identity=ci`, the path resolves to `.github/sts/my-app/ci.sts.yaml`.

## Policy schema

| Field | Type | Description |
|---|---|---|
| `issuer` | `string` | OIDC `iss` claim (exact match) |
| `subject` | `string` | OIDC `sub` claim (exact match) |
| `subject_pattern` | `regex` | OIDC `sub` claim (regex, used when `subject` is absent) |
| `claim_pattern` | `map[string]regex` | Additional JWT claims to match |
| `audience` | `string` | **Required.** Expected OIDC `aud` claim. A policy without it would accept tokens minted for any other relying party sharing the issuer (cross-RP token reuse) and is rejected at parse time. |
| `repositories` | `list[string]` | Present in the schema but not applied in the exchange flow. Repo-level scope pins the token to the requested repository; centralized org-level policies pin it to the single repository derived from the OIDC subject. |
| `permissions` | `map[string]string` | GitHub App permissions (`read` / `write` / `admin`) |

> **`audience` is mandatory.** Every policy must declare the OIDC audience it trusts. The same value must be passed to `core.getIDToken(<audience>)` in the workflow that requests the token. A missing `audience:` is rejected at policy parse time; it would otherwise accept tokens minted for any other relying party that shares the issuer (cross-RP token reuse).

## Subject matching

Policies support two methods for matching the OIDC `sub` claim:

### Exact match (preferred)

Use `subject` for a literal, exact match. This is the most secure option.

```yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:org/repo:ref:refs/heads/main
audience: https://sts.example.com
permissions:
  contents: read
```

### Regex pattern

Use `subject_pattern` when you need to match a range of subjects (e.g., all branches, multiple repos).

```yaml
issuer: https://token.actions.githubusercontent.com
subject_pattern: "repo:org/repo:.*"
audience: https://sts.example.com
permissions:
  contents: read
```

> Prefer `subject` whenever possible. An exact match removes the ambiguity of a broad regex and makes the policy's scope explicit.

## Claim patterns

`claim_pattern` is a map of JWT claim names to regex patterns. Use it to require additional identity constraints beyond `iss` and `sub`.

```yaml
issuer: https://token.actions.githubusercontent.com
subject_pattern: "repo:org/repo:.*"
audience: https://sts.example.com
claim_pattern:
  job_workflow_ref: "org/repo/.github/workflows/deploy\\.yml@.*"
  repository_owner: "^myorg$"
permissions:
  deployments: write
```

This policy only matches workflows from `deploy.yml` in the `myorg` organization.

### Custom claims

GitHub Actions lets you attach custom claims to the OIDC token, including repository [custom properties](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect#customizing-the-token-claims). You can require these claims with `claim_pattern` to pin policies to a specific environment, deployment, or business property:

```yaml
issuer: https://token.actions.githubusercontent.com
subject_pattern: "repo:myorg/.*"
audience: https://sts.example.com
claim_pattern:
  repository_owner: "^myorg$"
  environment: "^production$"
permissions:
  deployments: write
```

For more on GitHub's OIDC token claims, see:

- [About security hardening with OpenID Connect](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [Immutable subject claims for GitHub Actions OIDC tokens](https://github.blog/changelog/2026-04-23-immutable-subject-claims-for-github-actions-oidc-tokens/)

## Organization-level scope

In addition to repo-level scope (`scope=org/repo`), github-sts supports **org-level scope** (`scope=myorg`).

Configure `org_policy_repo` to specify where org-level policies live:

```yaml
apps:
  default:
    app_id: 123456
    private_key_path: /etc/github-sts/keys/default.pem
    org_policy_repo: .github
```

Org-level policy example (placed in `myorg/.github/.github/sts/default/org-ci.sts.yaml`):

```yaml
issuer: https://token.actions.githubusercontent.com
subject_pattern: "repo:myorg/.*"
audience: https://sts.example.com
permissions:
  contents: read
  pull_requests: write
```

> A centralized org-level policy pins the issued token to the single repository derived from the OIDC `sub` claim; it does not grant org-wide access.

### Policy resolution

When the same identity has a policy file in both the requesting repo and the org policy repo, `policy_resolution` decides which one wins:

| Mode | Order | On collision | Use when |
|---|---|---|---|
| `org_first` *(default)* | org → repo fallback | **org wins** | Org admin owns identity names; repos may self-service identities the org has not claimed. |
| `repo_first` *(deprecated)* | repo → org fallback | repo wins | Backwards-compat only; allows repo owners to override the centralized policy. Emits a deprecation warning at startup. |
| `org_only` | org repo only, no fallback | n/a | Strictly forbid self-service. Repos cannot define their own policies. |

```yaml
apps:
  default:
    app_id: 123456
    private_key_path: /etc/github-sts/keys/default.pem
    org_policy_repo: .github
    policy_resolution: org_first
```

If `org_policy_repo` is unset, only the requesting repo is consulted regardless of mode.

## Next steps

- [Policy Recipes]({{< relref "/concepts/policy-recipes" >}}): copy-and-paste patterns for common scenarios
- [OIDC Issuers]({{< relref "/oidc-issuers" >}}): per-provider issuer setup
- [Security Model]({{< relref "/concepts/security-model" >}}): trust boundaries and threat model
