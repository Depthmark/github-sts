# Contributing to github-sts

github-sts exchanges OIDC tokens for short-lived, scoped GitHub installation tokens. Because it mints credentials, a change here can widen what a caller is allowed to do. That shapes how contributions are reviewed: correctness and blast radius come before convenience.

## Ways to contribute

Open an issue for anything you want changed. The [issue templates](https://github.com/Depthmark/github-sts/issues/new/choose) route it to the right place:

- **Bug report** for behaviour that contradicts the documentation.
- **Feature request** for a capability that does not exist yet.
- **Configuration help** when an exchange is rejected and you are not sure it is a defect. Most rejections are a trust policy or claim mismatch rather than a bug.
- **Documentation issue** for a page that is wrong, missing, or out of sync between English and French.

Never open a public issue for a vulnerability. See [Security](#security).

For anything larger than a small fix, open an issue before writing code. Agreeing on the approach is cheaper than rewriting a pull request.

## Development setup

You need Go 1.26.6 or newer, plus the tool each check depends on:

| Tool | Used by | Install |
|---|---|---|
| Go 1.26.6+ | `make build`, `make test` | [go.dev/dl](https://go.dev/dl/) |
| golangci-lint | `make lint` | [golangci-lint.run](https://golangci-lint.run/welcome/install/) |
| govulncheck | `make vuln-check` | `go install golang.org/x/vuln/cmd/govulncheck@latest` |
| OPA | `make test-rego` | [openpolicyagent.org](https://www.openpolicyagent.org/docs/latest/#running-opa) |
| check-jsonschema | `make validate-examples` | `pipx install check-jsonschema` |
| Docker | `make docker`, local OCI test | [docs.docker.com](https://docs.docker.com/get-docker/) |
| Hugo Extended | documentation targets | version pinned in `docs/.hugo-version` |
| Python 3 | documentation checks | any 3.x |

Each target that needs a tool checks for it first and tells you what to install, so you can add them as you go rather than all at once.

## The development loop

```bash
make build
make test          # or: make test-race
make lint
make ci            # lint, race tests, Rego tests, vuln check, build, example validation
```

`make ci` gathers the Go checks into one command. Continuous integration runs the same tools through a shared reusable workflow rather than through this target, so a clean `make ci` predicts a green pull request without guaranteeing one.

## Pull requests

Branch from `main`. Pull requests are squash merged, so **the pull request title becomes the commit message**, and release-please reads that message to build the changelog and choose the next version. Write the title as a [Conventional Commit](https://www.conventionalcommits.org/en/v1.0.0/):

```text
feat: exchange tokens for enterprise-scoped installations
fix: reject expired OIDC tokens before policy evaluation
docs: document the bundle enforcement modes
feat!: rename GITHUBSTS_APP_ID to GITHUBSTS_APP_DEFAULT_APP_ID
```

Types in use: `feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`. A `!` after the type marks a breaking change; describe the upgrade path in the pull request body. Only `feat` and `fix` produce a changelog entry and a version bump.

The pull request template asks for the release impact, how you tested, and the security considerations. Those three answers are what a reviewer reads first.

## Trust policy examples

Two sets of policies are validated against `internal/policy/yaml/schema_v1.json`:

- `config/examples/*.sts.yaml`, checked by `make validate-examples`
- `.github/sts/*/*.sts.yaml`, the policies this repository applies to itself, checked by `make validate-repository-policies`

Every policy example, in code or in documentation, follows the example rules in `docs/documentation-contract.md`: fictional credentials only (`123456`, `myorg`, `stsexample.com`), an explicit audience on every token request, pinned versions rather than `@main`, the minimum permissions the example needs, and `subject` rather than `subject_pattern` when an exact match will do.

## Documentation

English is the source language and French is required. A page that exists in one tree and not the other fails the build.

```bash
make docs-serve    # http://localhost:1313/github-sts/
make docs-check    # build, translation parity, links and anchors, writing standard
```

`make docs-check` and `.github/workflows/docs-check.yml` run the same gates in the same order, so a clean local run means a clean check. It enforces:

- **Parity:** every page exists in both trees, declares `translationKey`, has the same heading count, and the French version reaches at least 75 percent of the English word count.
- **Links:** internal links and anchors resolved against the built site, because Hugo validates a `relref` target page but not its fragment.
- **Writing standard:** no em dash or en dash in prose, no unexplained hype, no generic AI phrasing.

`docs/documentation-contract.md` is the authority on structure, terminology, and how satellite repositories are imported. Read it before restructuring anything.

## GitHub Actions workflows

Pin every action and reusable workflow to a full commit SHA, with the release tag in a trailing comment:

```yaml
uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
```

A tag is mutable, and an action that is replaced upstream runs with the job's token. The repository is scored by [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/Depthmark/github-sts), which checks this.

## Security

Report vulnerabilities privately through [GitHub Security Advisories](https://github.com/Depthmark/github-sts/security/advisories/new). Do not open a public issue. Response times and the disclosure process are on the [Security page](https://depthmark.github.io/github-sts/resources/security/).

In every change, whatever its size:

- No real private keys, tokens, passwords, or production endpoints in code, tests, fixtures, or documentation.
- No key, token, or raw OIDC claim reaching a log line, an error message, or a metric label.
- If a change widens the scope, lifetime, or audience of a minted token, or changes which issuers or claims are trusted, say so in the pull request.

## License

github-sts is released under the [MIT License](LICENSE). Contributions are accepted under the same license.
