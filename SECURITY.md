# Security Policy

github-sts issues short-lived GitHub credentials, so a flaw in it can turn into
unauthorized access to someone's repositories. Reports are welcome and handled
as a priority.

## Supported versions

| Version | Status |
|---|---|
| `v0.0.x` (latest) | Supported |
| `v0.0.3` | Supported |

We support the latest release and one version back. Older versions do not
receive security patches.

## Reporting a vulnerability

**Do not open a public issue, pull request, or discussion for a security
report.** Use one of the two private channels below. Either one reaches the
maintainers; pick whichever is easier for you.

1. **GitHub private vulnerability reporting (preferred).** Open a report at
   [github.com/Depthmark/github-sts/security/advisories/new](https://github.com/Depthmark/github-sts/security/advisories/new).
   The report, the discussion, the draft advisory, and the CVE request all stay
   in one private thread that you keep access to.
2. **Email.** Write to
   [oss-security@depthmark.net](mailto:oss-security@depthmark.net) with
   `github-sts` in the subject line. Use this if you cannot or would rather not
   use GitHub.

Include as much of the following as you have:

- A description of the vulnerability and the impact you believe it has
- Steps to reproduce, or a proof of concept
- Affected versions, and the relevant configuration (OIDC issuer, trust policy,
  bundle enforcement mode) with any real secrets redacted
- Any fix or mitigation you would suggest

## Response timeline

| Stage | Target |
|---|---|
| Acknowledgment of your report | 48 hours |
| Initial assessment and severity | 5 business days |
| Fix and coordinated disclosure | agreed with you |

If 48 hours pass without an acknowledgment, assume the message went astray and
try the other channel.

## Disclosure policy

We follow coordinated disclosure. Please give us time to release a fix and give
operators time to upgrade before you publish anything. We publish a GitHub
Security Advisory for every confirmed vulnerability, request a CVE where one is
warranted, and credit you by the name and link you choose, or keep you anonymous
if you prefer.

## Scope

In scope: this repository, including the token exchange server, OIDC validation,
trust policy evaluation, Rego bundle enforcement, and the published
`ghcr.io/depthmark/github-sts` image. Findings in
[github-sts-action](https://github.com/Depthmark/github-sts-action) and
[github-sts-helm](https://github.com/Depthmark/github-sts-helm) can also be
reported through the channels above.

Out of scope: deployments you do not operate, scanner output with no
demonstrated impact on this software, and vulnerabilities in GitHub itself,
which belong in [GitHub's own program](https://bounty.github.com/). Please do
not test against a third party's github-sts instance, and do not access, alter,
or retain data that is not yours.

## Security model

For the trust boundaries and threat model behind these guarantees, see
[Security Model](https://depthmark.github.io/github-sts/concepts/security-model/)
and the [vulnerability reporting page](https://depthmark.github.io/github-sts/resources/security/)
on the documentation site.

## Acknowledgments

We thank the researchers who report vulnerabilities responsibly.

*None yet: be the first.*
