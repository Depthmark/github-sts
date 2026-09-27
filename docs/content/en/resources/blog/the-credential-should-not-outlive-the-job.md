---
title: The Credential Should Not Outlive the Job
description: Why we built github-sts, what it replaces, and what it costs to run.
date: 2026-09-21
authors: ["Alexandre Delisle"]
weight: 1
translationKey: credential-should-not-outlive-job
---

*September 21, 2026 · Alexandre Delisle*

## Making a credential is easy. That was the trap.

Creating a GitHub credential is easy. Open settings, pick some permissions, copy the value, and put it in a secret. The hard part starts after that.

Every credential is a small, lasting obligation. Someone has to know which job uses it, what it can reach, who owns its rotation, and what will break when it is revoked. The problem changes shape when the honest answer to "how many do we have?" is "I need to write a script to find out."

That is where github-sts started. Not with a breach, but with an inventory problem.

The project's maintainer describes thousands of deploy keys, service accounts with their own identity lifecycle, and more than one hundred consumer GitHub Apps spread across multiple organizations. Those are maintainer-provided measures of scale, not a normalized inventory. A GitHub App, an App installation, and an App private key are different objects. One App can have several installations and several private keys, so combining those counts would hide the work rather than explain it.

None of these mechanisms is inherently a bad choice. Each can be a sensible local answer. Together, they became a distributed credential-management system, assembled one reasonable decision at a time.

The recurring cost was coordination. Rotating a key meant finding every consumer before the old key stopped working. Removing a service account meant proving that no quiet scheduled job still depended on its memberships. An inventory could tell us what existed, but not always who still needed it or why it had its current reach. The organization did not need one more place to store credentials. It needed a different relationship between workload identity and GitHub access.

## Count what your token can see

You can take a first inventory with the GitHub command line interface (CLI). Authenticate first, then set the organization:

```bash
gh auth status
ORG=your-organization
```

[GitHub exposes deploy keys](https://docs.github.com/en/rest/deploy-keys/deploy-keys) per repository, not through one organization-wide endpoint. This script prints a total only after every visible repository request succeeds:

```bash
set -euo pipefail

inventory="$(
  gh api --paginate "/orgs/$ORG/repos?type=all&per_page=100" --jq '.[].full_name' |
  while IFS= read -r repository; do
    printf 'repository\t%s\n' "$repository"
    gh api --paginate "/repos/$repository/keys?per_page=100" \
      --jq '.[] | "deploy-key\t\(.id)"' || exit 1
  done |
  awk -F '\t' '
    $1 == "repository" { repositories++ }
    $1 == "deploy-key" { deploy_keys++ }
    END { printf "repositories_seen=%d\ndeploy_keys=%d\n", repositories, deploy_keys }
  '
)"
printf '%s\n' "$inventory"
```

The token needs repository `Metadata: read` to enumerate repositories and `Administration: read` to list deploy keys. It can silently omit private repositories it cannot see, so compare `repositories_seen` with an authoritative inventory. The script also makes at least one API request per repository.

Count App installations separately:

```bash
gh api "/orgs/$ORG/installations?per_page=1" --jq '.total_count'
```

[That call](https://docs.github.com/en/rest/orgs/orgs#list-app-installations-for-an-organization) requires organization-owner access, or a fine-grained token with organization `Administration: read`. Its result is an installation count, not a count of Apps or private keys. GitHub also provides no reliable API field that distinguishes machine users from people, so that inventory needs an organization-specific naming or ownership convention.

## Use the smallest mechanism that fits

[`GITHUB_TOKEN`](https://docs.github.com/en/actions/concepts/security/github_token) is the right answer for many workflows. GitHub issues it for the job, its permissions can be narrowed, and no standing key needs to be distributed. If a workflow acts only on its own repository, start there.

A GitHub App private key with [`actions/create-github-app-token`](https://github.com/actions/create-github-app-token) is also a good option for cross-repository automation that does not justify another service. It produces a short-lived installation token with the App's identity and permissions. The tradeoff is that the authorized workflow can read the standing private key used to mint that token. Rotation and distribution still belong to every secret store that holds the key.

github-sts is for the point where that distribution becomes the problem. It moves the App private key out of workloads and into a broker you operate.

## Identity, policy, token

[Cloud OIDC](https://docs.github.com/en/actions/concepts/security/openid-connect) established a useful exchange model: a workload can present short-lived evidence of its identity instead of receiving a standing secret. [Octo STS](https://github.com/octo-sts/app) was an early implementation of that idea for GitHub credentials, and it directly inspired github-sts.

The model separates three decisions:

1. OIDC proves which workload is asking.
2. Policy decides what that workload may request.
3. GitHub issues the resulting credential.

That separation matters. An expiry timer limits how long a stolen token works. It does not explain why the workload was allowed to receive the token in the first place.

Here is a representative label-sync job, using full commit SHAs verified for the named releases:

```yaml
name: Sync labels
on:
  schedule:
    - cron: '0 6 * * 1'

jobs:
  sync:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: Depthmark/github-sts-action@9014c80f47cad81e0a1295b112714d5c1b219d54 # v0.3.0
        id: sts
        with:
          sts-url: https://sts.example.com
          audience: https://sts.example.com
          scope: myorg/service-a
          identity: label-sync

      - name: Apply the shared label
        env:
          GH_TOKEN: ${{ steps.sts.outputs.token }}
        run: >-
          gh label create needs-triage
          --repo myorg/service-a
          --description "Awaiting triage"
          --color FBCA04
          --force
```

There is no `secrets.` reference in the authentication path. `id-token: write` lets the job request an OIDC identity token. github-sts validates that evidence, evaluates policy, and asks GitHub for a separate installation token. The workload never receives the broker's App private key, App JWT, or policy-read token.

The `scope` and `identity` inputs locate the authorization decision, not merely a token template. In this example, the target repository can define `.github/sts/default/label-sync.sts.yaml` to name the trusted source workflow and grant only `issues: write`. If the workload asks for permissions outside that ceiling, the exchange is denied. The policy stays reviewable beside the repository it protects, while an organization policy repository can take ownership when a central team needs to set the decision.

## The route github-sts chose

Every exchange selects one YAML trust policy, either from the target repository or a configured organization policy repository. `org_first` is the default resolution mode, so centralized policy wins when both locations define the same identity. The policy binds the request to an issuer, a mandatory audience, workload claims, allowed permissions, and exact source and target relationships.

The checks are intentionally ordered. The broker validates the OIDC issuer, signature, time claims, and audience before policy can authorize anything. It then verifies the GitHub identity, rejects a reused `jti`, resolves the requested App and exact repository target, loads one policy, evaluates claims and relationships, applies enterprise guardrails when configured, and only then asks GitHub to mint a token. A failed check stops the exchange. The OIDC token remains evidence throughout; it is never transformed into the GitHub credential.

For GitHub.com, those relationships use immutable numeric owner and repository IDs. Names can change or be reused. IDs keep a repository rename from becoming an authorization change.

The broker also reserves each OIDC token's `jti` to reject replay. The in-memory backend is suitable for one replica. Multi-replica deployments need `GITHUBSTS_JTI_BACKEND=redis` so every replica shares replay state.

The requested `scope` must name exactly one repository. Organization-wide token scope is intentionally rejected. A workload that needs three repositories makes three exchanges and receives three separately scoped tokens. That is more verbose, and it keeps each grant explicit.

Enterprise Rego bundles can add a central ceiling above the selected YAML policy. They are digest-pinned OCI artifacts, cosign verified, additive, and deny-wins. In the recommended `bundle_enforcement: required` posture, one global baseline is mandatory and fail-closed. Repository policy cannot weaken it. The [architecture documentation]({{< relref "/concepts/architecture" >}}) describes the complete ordered authorization pipeline.

## The complexity moved

github-sts does not make long-lived secrets disappear. The broker still holds one or more GitHub App private keys. It concentrates that authority so workloads cannot read it, which also concentrates the impact if the broker is compromised.

Operators own TLS, availability, upgrades, key rotation, monitoring, and incident response. The broker is on the authentication path, so an outage prevents dependent jobs from receiving tokens. Required bundles can fail closed when they cannot be verified or become older than `max_staleness`. Audit emission is asynchronous and buffered, so operators should [alert on dropped events and write errors]({{< relref "/integrations/monitor-usage" >}}) rather than assume every event was recorded.

That is the trade. Many distributed credential lifecycles become one security-sensitive operational boundary. Whether that exchange is worthwhile depends on the estate you counted at the beginning.

We do not yet have a reproducible number for the rotation hours saved or credentials retired, so this is a design criterion rather than a victory claim. The useful question is concrete: did centralizing the authority remove enough distributed ownership, storage, and rotation work to justify operating the broker? Teams with a handful of workflows may reasonably answer no. Teams that can no longer explain their credential inventory may answer differently.

The credential should not outlive the job. The authorization decision should not be lost when the job ends, either. An expiry timer handles the first requirement. Identity and policy are what make the second one answerable.
