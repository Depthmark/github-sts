---
name: wire-workflow
description: Add a github-sts token exchange to a GitHub Actions workflow with Depthmark/github-sts-action, matching an existing trust policy. Use when a repository owner has a trust policy (.sts.yaml) and wants a workflow or job to obtain and use the GitHub token, asks how to call github-sts from Actions, or wants a workflow's personal access token or App key secret replaced by a github-sts exchange.
---

# Wire a workflow to github-sts

The job asks GitHub for an OIDC token, the action sends it to the github-sts broker, and the broker returns a GitHub App installation token if a trust policy allows it. Three values in the workflow must equal the policy's exactly. A mismatch returns only a `code` and a `trace_id`, so read the values from the policy file instead of retyping them.

Do not call the broker from this skill.

## 1. Find the trust policy

The policy lives in the **target** repository, the one the token acts on, at `.github/sts/APP/IDENTITY.sts.yaml`. If there is none, write it first with the `write-trust-policy` skill.

Read these from the file and its path. Ask the user only for the broker URL.

| Workflow input | Source |
| --- | --- |
| `app` | The directory name under `.github/sts/` |
| `identity` | The file name without `.sts.yaml` |
| `audience` | The policy's `audience` value, character for character |
| `scope` | The target repository as `OWNER/REPO` |
| `sts-url` | The base URL of the broker, from the platform admin. It is often the same string as the audience, but do not assume so. |

## 2. Check that the policy admits this workflow

Before editing, compare the policy with the workflow you are about to change:

- The workflow's repository must be one of the policy's `github.sources`. Compare with `gh api repos/OWNER/REPO --jq '{owner_id: (.owner.id | tostring), repository_id: (.id | tostring)}'`.
- The policy's selector must match the runs that will reach the job. A policy with `ref: refs/heads/main` under `claim_pattern` rejects a run on a pull request or on another branch, so the job's triggers or its `if:` must agree with it.
- What the job does with the token must fit inside the policy's `permissions`.

If one of these fails, tell the user and fix the policy or the trigger first. Do not widen a policy without the user agreeing to it.

## 3. Pin the action

Pin `Depthmark/github-sts-action` to a full commit SHA, with the release tag in a trailing comment. Resolve the latest release instead of copying a SHA from memory:

```bash
tag=$(gh api repos/Depthmark/github-sts-action/releases/latest --jq .tag_name)
sha=$(gh api "repos/Depthmark/github-sts-action/commits/$tag" --jq .sha)
echo "Depthmark/github-sts-action@$sha # $tag"
```

If that cannot run, use the pin shown below, which is release `v0.3.0`, and say so.

## 4. Add the job

```yaml
permissions: {}

jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: Depthmark/github-sts-action@9014c80f47cad81e0a1295b112714d5c1b219d54 # v0.3.0
        id: sts
        with:
          sts-url: https://sts.example.com
          audience: https://sts.example.com
          scope: myorg/myrepo
          app: default
          identity: ci

      - name: Use the token
        env:
          GH_TOKEN: ${{ steps.sts.outputs.token }}
        run: gh api repos/myorg/myrepo --jq .full_name
```

Rules that hold for every workflow:

- `id-token: write` goes on the job that runs the action, never at the top of the workflow. A job without it cannot request an OIDC token.
- Setting `permissions` on a job removes every permission not listed. Keep the ones the job already had, and add `contents: read` if the job checks out the repository with the default token.
- Always set `audience`. The action's default is `github-sts`, which only works if the policy says the same.
- Always set `app`, to the directory name from step 1.
- When editing an existing workflow, add the step and the permission to the job that needs the token and leave the other jobs alone.

## 5. Use the token

The token is in `steps.sts.outputs.token`. Pass it only to the steps that need it, through `env` or a `with` input:

```yaml
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          repository: myorg/myrepo
          token: ${{ steps.sts.outputs.token }}
```

Never print the token, write it to a file, or expose it as a job output. If the workflow used a personal access token or an App key from `secrets`, replace each use with the step output and tell the user which secret can now be deleted.

## 6. Verify before handing over

Re-read both files and confirm each line:

1. `audience`, `app` and `identity` in the workflow equal the policy's audience, directory and file name.
2. `scope` is the repository named by the policy's `github.target`.
3. `id-token: write` appears once, on the job, and the workflow has no top-level `id-token`.
4. The action is pinned to a 40-character SHA with its tag in a comment.

State what was checked and what could not be. The exchange itself can only be proven by a run, after the policy is on the target repository's default branch.

## If the run fails

The action sets `steps.sts.outputs.error-code`. The codes a repository owner can act on alone:

| Code | Check |
| --- | --- |
| `audience_mismatch` | `audience` in the workflow against the policy. If they agree, the broker requires a different audience: ask the platform admin. |
| `app_unknown` | The `app` input against the name the platform admin gave. |
| `policy_not_found` | The path, the file name, and whether the policy is on the target's default branch. |
| `trust_policy_invalid` | Validate the policy against the schema again. |
| `github_identity_invalid` | The source repository has not opted in to immutable subject claims. |
| `policy_denied` | The selector against the run's branch or workflow, and the IDs in `github.sources` and `github.target`. |
| `action_missing_oidc_env` | `id-token: write` is missing on the job. |

For any other code, or when these checks pass, give the platform admin the `trace_id` from the job log. Only the broker's audit log holds the reason.
