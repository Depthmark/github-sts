---
name: write-trust-policy
description: Write a github-sts trust policy file (.github/sts/{app}/{identity}.sts.yaml) for a GitHub Actions workflow and validate it against the published schema. Use when a repository owner wants a workflow to obtain a GitHub token from github-sts, asks for a trust policy or an .sts.yaml file, or wants to replace a personal access token or a GitHub App key in CI with a github-sts token exchange.
---

# Write a github-sts trust policy

A trust policy tells the github-sts broker which workflow may obtain a GitHub App installation token for a repository, and with which permissions. A rejected exchange returns only a `code` and a `trace_id`, and the reason stays in the broker's audit log, which the repository owner cannot read. Get every value from its source so the first exchange works.

Do not call the broker from this skill. Validation uses the published schema only.

## 1. Collect the inputs

Ask for whatever is missing. Never guess a value in this table.

| Input | Where it comes from |
| --- | --- |
| Target repository | The `OWNER/REPO` the token will act on. The policy file lives there. |
| Source repositories | Each `OWNER/REPO` whose workflow asks for the token. Often the same as the target. |
| App name | The platform admin who runs github-sts. It is the name the broker gives the GitHub App, not the App's slug on GitHub. |
| Audience | The platform admin. It is one fixed string per github-sts deployment, such as `https://sts.example.com`. |
| Identity | A short name you choose with the user for this use, such as `ci` or `release`. Letters, digits, `.`, `_` and `-` only, 100 characters at most, no `/`. |
| Workload | Which runs may ask: a branch, a workflow file, or a deployment environment. |
| Permissions | What the job does with the token. |

If the App name or the audience is unknown, stop and tell the user to ask the platform admin. A guess validates and then fails at exchange with `app_unknown` or `audience_mismatch`.

## 2. Read the immutable IDs from GitHub

The policy names repositories by numeric ID, never by name. Run this once for the target and once for each source, and copy the output. Never type an ID from memory or from an example.

```bash
gh api repos/OWNER/REPO --jq '{owner_id: (.owner.id | tostring), repository_id: (.id | tostring), created_at: .created_at}'
```

Without `gh`, call `https://api.github.com/repos/OWNER/REPO` with `curl` and read `.owner.id`, `.id` and `.created_at`. A private repository needs a token in the `Authorization` header.

If a source `owner_id` differs from the target `owner_id`, the request crosses organizations. Tell the user that the broker may deny it unless the platform admin has registered an exception, and get their confirmation before writing the file.

## 3. Check the immutable subject setting on each source

By default the broker only accepts GitHub Actions tokens whose subject carries the IDs, in the form `repo:OWNER@OWNER-ID/REPO@REPO-ID:...`.

- A source repository created on or after 2026-07-15 issues that form already.
- An older one must opt in, in its own or its organization's Actions OIDC settings on GitHub.

For an older source, ask the user whether it has opted in. Do not change the setting yourself: it changes the subject of every OIDC token the repository issues, which can break cloud roles or other services that match on the old form. If it has not opted in, write the policy anyway and say plainly that the exchange returns `github_identity_invalid` until it does.

## 4. Choose the workload selector

A policy needs at least one selector. The `github` block already pins which repositories are involved, so the selector only narrows which runs qualify. Prefer `claim_pattern`, because the claims below keep the same value whatever the subject format.

| The token is for | Selector |
| --- | --- |
| Runs on one branch | `claim_pattern` with `ref: refs/heads/main` |
| One workflow file on one branch | `claim_pattern` with `job_workflow_ref: 'OWNER/REPO/\.github/workflows/FILE\.yml@refs/heads/main'` |
| Jobs that target a deployment environment | `claim_pattern` with `environment: production` |

Rules for the values:

- Each value is a regular expression that the broker anchors on both ends. Escape literal dots, and put the value in single quotes so the backslash survives YAML.
- Several entries under `claim_pattern` must all match.
- Never write a value that matches everything, such as `.*`, as the only selector. Narrow to what the user named.
- `subject` and `subject_pattern` also exist, and are mutually exclusive. Use `subject` only when the user gives the exact subject string of a token they decoded.

## 5. Choose the permissions

- List only what the job needs, at the lowest level that works. The block is a ceiling: a workflow can ask for less at exchange time, never for more.
- Use GitHub App permission names with underscores: `contents`, `pull_requests`, `issues`, `actions`, `checks`, `packages`, `statuses`, `deployments`. The full list is the `permissions` properties of the schema.
- Levels are `read` or `write`. `workflows` and `profile` accept `write` only.
- The GitHub App must itself hold each permission at that level or higher. Only the platform admin can confirm that. A policy that asks for more still validates and then fails at exchange, so name the permissions when you ask the admin.

## 6. Write the file

Write it in the **target** repository, at `.github/sts/APP/IDENTITY.sts.yaml`, with the App name and the identity from step 1 as the directory and the file name. The schema accepts no other top-level fields than the ones shown here plus `subject` and `subject_pattern`.

```yaml
# yaml-language-server: $schema=https://depthmark.github.io/github-sts/schemas/sts/v1/trust-policy.json
issuer: https://token.actions.githubusercontent.com
audience: https://sts.example.com
claim_pattern:
  ref: refs/heads/main
github:
  sources:
    - owner_id: "123456"
      repository_id: "456789"
  target:
    owner_id: "123456"
    repository_id: "456789"
permissions:
  contents: read
```

Replace every value below `issuer`:

- `audience` is the admin's string, character for character.
- `github.sources` holds one entry per source repository, and `github.target` is the target. For a workflow that asks for a token on its own repository, the two are identical.
- Every ID is a quoted string, `"123456"` and not `123456`.
- `issuer` stays as shown for workflows on GitHub.com.

## 7. Validate against the schema

```bash
check-jsonschema \
  --schemafile https://depthmark.github.io/github-sts/schemas/sts/v1/trust-policy.json \
  .github/sts/APP/IDENTITY.sts.yaml
```

Install the tool with `pipx install check-jsonschema`, or run it once with `uvx check-jsonschema`. Fix the file until it passes. If the tool cannot be installed, say that the file was not validated instead of claiming it was.

Then run the `gh api` command from step 2 again and compare its output with the file. The schema proves the shape of an ID, not that it is the right one, and it does not compile the regular expressions.

## 8. Hand over

Tell the user, in this order:

1. The file path, and that the broker reads it from the target repository's default branch, so it has no effect until it is merged there.
2. The four values the workflow must repeat exactly: `audience`, `app`, `identity`, and `scope` (the target `OWNER/REPO`).
3. Anything still unconfirmed: the immutable subject setting, the App's own permissions, or a cross-organization exception.
4. If the platform admin centralizes policies in an organization policy repository, a policy there with the same identity may take precedence over this file.

To add the token exchange to a workflow, continue with the `wire-workflow` skill.
