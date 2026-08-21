---
title: Security
description: Supported versions, vulnerability reporting process, and safe disclosure policy.
weight: 3
translationKey: security
---

## Supported versions

| Version | Status |
|---|---|
| `v0.0.x` (latest) | Supported |
| `v0.0.3` | Supported |

We support the latest release and one version back. Older versions do not receive security patches.

## Reporting a vulnerability

**Do not open a public issue.** Instead, report vulnerabilities privately:

1. Use GitHub's [private vulnerability reporting](https://github.com/Depthmark/github-sts/security/advisories/new) (preferred)
2. Or email the maintainers directly

Include:

- A description of the vulnerability
- Steps to reproduce
- Affected versions
- Any suggested fixes

## Response timeline

1. **Acknowledgment:** Within 48 hours
2. **Assessment:** Within 5 business days
3. **Fix and disclosure:** Coordinated with the reporter

We follow a coordinated disclosure process. We ask that you not publicly disclose the vulnerability until we have released a fix and users have had time to upgrade.

## Supply-chain security score

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Depthmark/github-sts/badge)](https://scorecard.dev/viewer/?uri=github.com/Depthmark/github-sts)

[OpenSSF Scorecard](https://github.com/ossf/scorecard) evaluates the repository's supply-chain security practices after changes reach `main` and on a weekly schedule. Public results become available in the [Scorecard viewer](https://scorecard.dev/viewer/?uri=github.com/Depthmark/github-sts) after the first successful scan. Maintainers with repository write access can review actionable findings as code scanning alerts in the [Security tab](https://github.com/Depthmark/github-sts/security/code-scanning).

Scorecard checks are automated heuristics, not a security certification. Review individual checks and their remediation guidance instead of relying only on the aggregate score.

## Security model

For the full security model, see [Security Model]({{< relref "/concepts/security-model" >}}).

## Acknowledgments

We thank the following researchers for responsibly disclosing vulnerabilities:

*None yet: be the first.*
