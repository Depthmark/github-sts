---
title: Policy Recipes
description: Copy-and-paste trust policy patterns for exact repository matching, workflow restrictions, cross-repository, and organization-level policies.
weight: 4
translationKey: policy-recipes
---

Ready-to-use trust policy patterns for common scenarios. Replace the placeholder values with your own.

## Exact repository, exact branch

Most secure: a single workflow from a specific branch.

```yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:myorg/myrepo:ref:refs/heads/main
audience: https://sts.example.com
permissions:
  contents: read
  issues: write
```

## Workflow-restricted

Restrict to a specific workflow file, any branch.

```yaml
issuer: https://token.actions.githubusercontent.com
subject_pattern: "repo:myorg/myrepo:.*"
audience: https://sts.example.com
claim_pattern:
  job_workflow_ref: "myorg/myrepo/.github/workflows/deploy\\.yml@.*"
permissions:
  deployments: write
  statuses: write
```

## Organization-policy (centralized)

Placed in `myorg/.github/.github/sts/default/release-bot.sts.yaml`, this policy lets workflows from the `release` repository obtain write access. A centralized policy is scoped to the single repository derived from the OIDC `sub` claim, not the whole organization.

```yaml
issuer: https://token.actions.githubusercontent.com
subject_pattern: "repo:myorg/release:.*"
audience: https://sts.example.com
permissions:
  contents: write
  pull_requests: write
```

## Azure workload identity

For Azure-based workloads using Entra ID.

```yaml
issuer: https://login.microsoftonline.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/v2.0
subject_pattern: "[a-f0-9-]+"
audience: https://sts.example.com
claim_pattern:
  azp: "your-azure-app-client-id"
permissions:
  contents: read
```

## Environment-restricted

Only tokens from a specific GitHub environment.

```yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:myorg/myrepo:environment:production
audience: https://sts.example.com
claim_pattern:
  repository_owner: "^myorg$"
permissions:
  deployments: write
  contents: read
```

## Pull request workflows (read-only)

Safe pattern for PR workflows that need read access.

```yaml
issuer: https://token.actions.githubusercontent.com
subject_pattern: "repo:myorg/myrepo:ref:refs/pull/.*"
audience: https://sts.example.com
permissions:
  contents: read
  pull_requests: read
  metadata: read
```

## Restrict to a subject without a fixed ref

The `immutable_subject` field is not part of the current schema; unknown keys are ignored by the YAML parser. To restrict a policy to a single branch, put the exact value in `subject`. To match a range, use `subject_pattern`.

**Exact:**

```yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:myorg/myrepo:ref:refs/heads/main
audience: https://sts.example.com
permissions:
  contents: read
```

**Regex:**

```yaml
issuer: https://token.actions.githubusercontent.com
subject_pattern: "repo:myorg/myrepo:.*"
audience: https://sts.example.com
permissions:
  contents: read
```

> **Note:** The `audience` field is mandatory. Add it to any policy that was written for an older version.
