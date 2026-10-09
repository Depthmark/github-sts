---
title: Agent skills
description: Install the skills that let a coding agent write a trust policy and wire a GitHub Actions workflow to github-sts.
weight: 8
translationKey: agent-skills
---

github-sts ships two skills for repository owners. With them, a coding agent writes a trust policy that validates and a workflow that exchanges a token, using values it reads from GitHub instead of values you copy by hand.

| Skill | What it does |
|---|---|
| `write-trust-policy` | Looks up the immutable owner and repository IDs, writes `.github/sts/{app}/{identity}.sts.yaml` in the target repository, and validates it against the [published schema]({{< relref "/reference/policy-schema" >}}). |
| `wire-workflow` | Adds the exchange step to a workflow with a pinned `Depthmark/github-sts-action`, `id-token: write` on the job only, and the same `audience`, `app` and `identity` as the policy. |

The skills never call your github-sts server and hold no credential. They read repository metadata with the `gh` command you are already signed in to, and they validate against the static schema.

## Before you start

Ask the platform admin who runs github-sts for three values. The skills ask for them and do not guess.

1. The base URL of the server, such as `https://sts.example.com`.
2. The audience the server expects, which is often the same URL.
3. The name of the GitHub App as configured on the server, such as `default`.

You also need the [`gh` command](https://cli.github.com/), signed in with read access to the repositories involved.

## Install in Claude Code

Run these two commands inside Claude Code:

```text
/plugin marketplace add Depthmark/github-sts
/plugin install github-sts@depthmark
```

## Install in GitHub Copilot CLI

Run these two commands in a terminal:

```bash
copilot plugin marketplace add Depthmark/github-sts
copilot plugin install github-sts@depthmark
```

## Install without a plugin

Each skill is a plain folder with one `SKILL.md` file, in the open Agent Skills format. Any agent that reads that format can use a copy. Copy `skills/write-trust-policy` and `skills/wire-workflow` from a [release](https://github.com/Depthmark/github-sts/releases) of github-sts into the skills directory your agent reads, for example `.claude/skills/` or `.github/skills/` in your repository.

A copied skill does not update itself. Copy it again when you upgrade github-sts.

## Use the skills

Open the agent in the repository that will receive the token, and describe the goal:

```text
Write a github-sts trust policy so the release workflow on main can open pull requests in this repository.
```

When the policy exists, ask for the workflow:

```text
Wire the release workflow to github-sts with that policy.
```

Review both files before you merge them. The trust policy takes effect once it is on the default branch of the target repository, and it decides who can obtain a token, so treat it like any other access change.

## Versions

The skills have no version of their own. They are released with github-sts, and the plugin reports the github-sts version it came from. A skill and a server at the same version agree on the policy schema and on the error codes, so update the plugin when the platform admin upgrades the server.

## What the skills do not cover

- **The reason for a denial.** A rejected exchange returns a `code` and a `trace_id`. `wire-workflow` lists what you can check alone for each code, and the platform admin finds the rest in the audit log. See [Troubleshooting]({{< relref "/operations/troubleshooting" >}}).
- **Cross-organization exceptions.** A workflow in one organization that requests a token for another may need an entry in the enterprise bundle. See [Trust Policies]({{< relref "/concepts/trust-policies" >}}).
- **The permissions of the GitHub App.** A policy cannot grant more than the App holds, and only the platform admin can see that ceiling.
