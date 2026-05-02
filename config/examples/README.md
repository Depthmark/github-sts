# Trust Policy Examples

This directory contains ready-to-use trust policy templates for common GitHub App
use cases. Each file is a valid `.sts.yaml` policy that can be placed in your
repository at `.github/sts/{app_name}/{identity}.sts.yaml`.

## Use Cases

| File | Description |
|------|-------------|
| `ci-readonly.sts.yaml` | Read-only CI — clone, read issues, read packages |
| `ci-deploy.sts.yaml` | CD pipeline — deploy + update statuses |
| `release-automation.sts.yaml` | Release bot — create releases, push tags, publish packages |
| `pr-automation.sts.yaml` | PR bot — manage PRs, checks, labels, reviews |
| `dependabot-style.sts.yaml` | Dependency updater — contents write, PRs, security alerts |
| `security-scanner.sts.yaml` | Security scanner — read code, write security alerts |
| `issue-triage-bot.sts.yaml` | Issue triage — manage issues, labels, projects |
| `org-admin.sts.yaml` | Org-level governance — members, hooks, audit (org scope) |
| `monorepo-selective.sts.yaml` | Monorepo — org scope restricted to specific repos |
| `gitops-controller.sts.yaml` | GitOps / ArgoCD — contents + deployments + environments |
| `pages-deploy.sts.yaml` | GitHub Pages — build and deploy static sites |
| `external-ci.sts.yaml` | External CI (e.g. Jenkins, CircleCI via Google OIDC) |

## How to Use

1. Copy the relevant template to your repository:
   ```bash
   mkdir -p .github/sts/my-app/
   cp ci-readonly.sts.yaml .github/sts/my-app/ci.sts.yaml
   ```

2. Edit the `issuer`, `subject`/`subject_pattern`, and `claim_pattern` fields
   to match your identity provider and workload identity.

3. Adjust `permissions` to follow least-privilege for your specific needs.

4. For org-level scope, place the policy in your org's `.github` repository
   and set `org_policy_repo: ".github"` in your github-sts server config.
