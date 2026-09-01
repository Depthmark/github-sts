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
| `github.sources` | `list[{owner_id, repository_id}]` | **Required for GitHub.com.** Exact immutable source repositories allowed to use the policy. |
| `github.target` | `{owner_id, repository_id}` | **Required for GitHub.com.** Exact immutable target repository for the minted token. |
| `permissions` | `map[string]string` | GitHub App permissions (`read` / `write` / `admin`). A **ceiling**, not a fixed grant: a caller may request a subset, or a lower level, and receive a token limited to that. |

> **`permissions` is a ceiling.** It is the most a matching workload may ever obtain, not what every token carries. A caller that omits the field gets exactly this set; one that asks for less gets less. Requesting a permission the policy does not name, or a level above what it names, is rejected before any token is minted. Write policies for the widest legitimate use of an identity and let each caller narrow to what its job needs -- see [Requesting less privilege]({{< relref "/reference/api#requesting-less-privilege" >}}).

> **`audience` is mandatory.** Every policy must declare the OIDC audience it trusts. The same value must be passed to `core.getIDToken(<audience>)` in the workflow that requests the token. A missing `audience:` is rejected at policy parse time; it would otherwise accept tokens minted for any other relying party that shares the issuer (cross-RP token reuse).

Every policy requires at least one workload selector: `subject`, `subject_pattern`, or a non-empty `claim_pattern`. Keep workload selectors focused on context such as `ref` or workflow path; immutable source and target identity belongs in `github` so repository renames retain the same authorization. `github.sources[]` and `github.target` entries are looked up by numeric `owner_id` / `repository_id`; see [OIDC Issuers → Getting the immutable owner and repository IDs]({{< relref "/oidc-issuers/github-actions#getting-the-immutable-owner-and-repository-ids" >}}) for how to find those values with the GitHub API before writing a policy.

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

## Examples with immutable GitHub identity

A GitHub.com policy combines a workload selector (above) with `github.sources`/`github.target`. Both are looked up by numeric `owner_id` / `repository_id`.

**Repo A → repo A (same repository, exact immutable source and target with a branch selector):**

The most common case: a workflow in a repository requesting a token scoped back to that same repository. `source` and `target` carry identical `owner_id`/`repository_id`.

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

This policy file lives **in repo B** (`.github/sts/{app}/{identity}.sts.yaml` of the target repo) and lists repo A as an allowed source. Same `owner_id` on both sides means this authorizes purely on the trust policy: no enterprise bundle exception is required regardless of `bundle_enforcement` posture, because the `sts.enterprise.v1` baseline's `same_owner` rule allows it directly. `github.sources[]` accepts multiple entries, so repo B can trust several source repos at once:

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

See [`config/examples/cross-repo-ci.sts.yaml`](https://github.com/Depthmark/github-sts/blob/main/config/examples/cross-repo-ci.sts.yaml) for a runnable version with two trusted sources.

**Repo A → repo B (cross-organization):**

`owner_id` differs between `source` and `target`, so this is a cross-organization relationship. The trust policy alone is enough under `bundle_enforcement: optional` (YAML-only authorization). Under `required` mode the mandatory `sts.enterprise.v1` baseline's `same_owner` check fails and the exchange is denied with `rule_id: sts.relationship.cross_org` **unless** the enterprise bundle's data document also carries a matching, unexpired `cross_org_exceptions` entry for this exact source/target/app/identity. See [Enterprise Rego bundles]({{< relref "/reference/configuration#enterprise-rego-bundles" >}}).

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

Required mode also needs a corresponding enterprise data entry. See [Enterprise Rego bundles]({{< relref "/reference/configuration#enterprise-rego-bundles" >}}) for the full `cross_org_exceptions` shape and admission rules.

## Organization-level scope

Organization-level requests (`scope=org`) are currently rejected. Use an exact repository scope (`scope=org/repo`); the broker resolves the current canonical name to immutable owner/repository IDs and mints with `repository_ids`.

This fail-closed restriction remains until typed immutable repository sets and explicit organization-wide grants are covered by mandatory enterprise policy. `org_policy_repo` may still centralize policy files for repository-scoped requests; it does not enable organization-wide tokens.

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
