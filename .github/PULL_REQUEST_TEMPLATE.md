<!--
The PR title becomes the squash-merge commit message, and release-please builds the
changelog and the next version from it. Write it as a Conventional Commit:

  feat: exchange tokens for enterprise-scoped installations
  fix: reject expired OIDC tokens before policy evaluation
  feat!: rename GITHUBSTS_APP_ID to GITHUBSTS_APP_DEFAULT_APP_ID

Types: feat, fix, docs, refactor, perf, test, build, ci, chore.
Append `!` for a breaking change and explain the migration under "Release impact".
-->

## What this changes

<!-- What behaviour is different after this merges. -->

## Why

<!-- The problem this solves. Link the issue: "Fixes #123", or "N/A" if there is none. -->

Fixes #

## Release impact

<!--
Delete the lines that do not apply.

- No user-facing change (refactor, test, or internal cleanup).
- User-facing change, described by the PR title above.
- Breaking change: what breaks, and what an operator has to do to upgrade.
-->

## How this was tested

<!--
What you actually ran, not what CI will run. For token exchange, OIDC verification, or
policy changes, say which claims and policies you exercised and what the decision was.
-->

## Security considerations

<!--
Answer if this touches token minting, OIDC verification, policy evaluation, App
credentials, or anything that reaches a log. Otherwise write "None".

- Does it widen the scope, lifetime, or audience of a minted token?
- Does it change which claims or issuers are trusted?
- Could any new log line, error, or metric label carry a key, token, or claim?
-->

## Checklist

- [ ] PR title follows [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).
- [ ] `make ci` passes locally (lint, race tests, Rego tests, vuln check, build, example validation).
- [ ] Tests cover the new behaviour, including the rejection paths.
- [ ] Docs updated in both `docs/content/en/` and `docs/content/fr/`, and `make docs-check` passes.
- [ ] New or changed configuration is reflected in `config/github-sts.example.yaml` and the configuration reference.
- [ ] Any GitHub Actions or reusable workflows are pinned to a full commit SHA with the version in a trailing comment.
- [ ] No secrets, private keys, tokens, or raw OIDC claims in code, tests, fixtures, or log output.
