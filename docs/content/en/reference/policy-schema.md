---
title: Trust Policy Schema
description: Published JSON Schema for trust policy files, editor setup, command-line validation, and the limits of structural validation.
weight: 5
translationKey: policy-schema
---

github-sts publishes a JSON Schema for trust policy files. Point an editor at
it and `.sts.yaml` files are validated as you type, with completion for field
names and permission values.

## Schema URL

```
https://depthmark.github.io/github-sts/schemas/sts/v1/trust-policy.json
```

The schema describes the file format documented in
[Trust Policies]({{< relref "/concepts/trust-policies" >}}): the files stored at
`.github/sts/{app}/{identity}.sts.yaml`.

This is a static file served from the documentation site. It needs no running
broker and no authentication. It is a different artifact from the
`GET /sts/v1/trust-policy.json` endpoint described in the
[API Reference]({{< relref "/reference/api" >}}), which republishes whatever
schema the loaded Rego bundle ships and is intended for operators of a
customised policy bundle.

## Editor setup

### Per file

Add one comment as the first line of a policy file. Editors backed by the YAML
language server read it, which covers VS Code with the Red Hat YAML extension,
IntelliJ IDEA, Neovim with `yamlls`, and Zed.

```yaml
# yaml-language-server: $schema=https://depthmark.github.io/github-sts/schemas/sts/v1/trust-policy.json
issuer: https://token.actions.githubusercontent.com
audience: https://sts.example.com
subject: "repo:myorg/myrepo:ref:refs/heads/main"
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

The comment is inert at exchange time. The broker parses fields, not comments.

### Per workspace

To validate every policy file without editing each one, associate the schema by
path in `.vscode/settings.json`:

```json
{
  "yaml.schemas": {
    "https://depthmark.github.io/github-sts/schemas/sts/v1/trust-policy.json": "**/*.sts.yaml"
  }
}
```

The pattern is matched against the full path of the open document, so begin it
with `**/` rather than with a workspace-relative fragment. To scope the
association more tightly than the file suffix does, use
`**/.github/sts/*/*.sts.yaml`.

## Command line

```bash
pipx install check-jsonschema

check-jsonschema \
  --schemafile https://depthmark.github.io/github-sts/schemas/sts/v1/trust-policy.json \
  .github/sts/*/*.sts.yaml
```

## Continuous integration

Gate policy changes on the schema before they reach the broker. A malformed
policy that merges is not detected until a workload tries to exchange a token
and receives a `403`.

```yaml
name: Validate trust policies

on:
  pull_request:
    paths:
      - '.github/sts/**'

permissions: {}

jobs:
  schema:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - run: pipx install check-jsonschema
      - run: |
          check-jsonschema \
            --schemafile https://depthmark.github.io/github-sts/schemas/sts/v1/trust-policy.json \
            .github/sts/*/*.sts.yaml
```

## What the schema checks

| Rule | Detail |
|---|---|
| Required fields | `issuer`, `audience`, and `permissions` must be present |
| Unknown fields | Any field outside the documented set is rejected |
| Identity selector | At least one of `subject`, `subject_pattern`, or `claim_pattern` |
| Selector conflict | `subject` and `subject_pattern` are mutually exclusive |
| GitHub binding | `github` is required for the GitHub Actions issuer and forbidden for every other issuer |
| Permission names | Only the permission names GitHub accepts for installation tokens |
| Permission values | The levels GitHub accepts for that specific permission, not a uniform set |
| Immutable IDs | `owner_id` and `repository_id` must be quoted non-zero decimal strings |
| Duplicate sources | `github.sources` entries must be unique |

## What the schema does not check

A JSON Schema validates structure. Several rules the broker enforces cannot be
expressed structurally, so a file that passes the schema can still be rejected
at exchange time:

- **Regex validity.** `subject_pattern` and `claim_pattern` values are compiled
  by the broker as anchored RE2 expressions. A pattern that is well-formed YAML
  but not a valid expression fails only when the broker loads the policy.
- **Real identifiers.** `owner_id` and `repository_id` are checked for shape,
  not for existence. A typo that stays numeric passes the schema and then fails
  to match the presented token.
- **Enterprise guardrails.** Rego bundles apply organization-wide permission
  ceilings and deny rules. They are evaluated during the exchange, against the
  request, and are invisible to a schema.
- **Installation state.** Whether the GitHub App is installed on the target
  repository with the permissions the policy grants.

### Permission levels are per permission

There is no single set of levels. GitHub accepts `read` or `write` for most
permissions, `admin` for only four (`organization_custom_properties`,
`organization_projects`, `repository_projects`, and
`enterprise_custom_properties_for_organizations`), `read` alone for
`organization_events` and `organization_plan`, and `write` alone for `profile`
and `workflows`.

The schema encodes each permission's own set, so `contents: admin` and
`workflows: read` are both rejected while you write the file rather than by the
GitHub API with a `422` when a workload first tries to exchange a token. The
source is GitHub's published OpenAPI description, specifically the
`app-permissions` schema that the create-installation-access-token request body
declares. Maintainers can diff the two with `make check-github-permissions`.

Two further notes on messages rather than outcomes. An unsupported
`repositories` field is rejected as an unrecognised field, whereas the broker
explains that organization-level scopes are disabled. Setting a permission to
`none` is rejected by both; omit the key instead, which is how this format
expresses an ungranted permission.

For the rules above that a schema cannot reach, post a policy to the broker's
`POST /sts/v1/trust-policy/validate` endpoint, documented in the
[API Reference]({{< relref "/reference/api" >}}). It runs the same validation
the exchange path runs and returns diagnostics with line and column numbers.

## Stability

The `v1` path accepts additive changes only. New optional fields and new
permission names may appear. No field is removed, no field becomes required,
and no pattern is tightened. A change that would break existing policies is
published under a `v2` path, and `v1` keeps serving.

The schema is generated from the broker's own source tree and published by the
documentation build, and tests pin its permission list to the one the broker
enforces. A permission the schema accepts is a permission the broker accepts.
