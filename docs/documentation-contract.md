# Documentation Contract

Version: 2.0.0
Last updated: 2026-08-19

This contract defines the shared documentation standards for the github-sts ecosystem:
**github-sts**, **github-sts-helm**, and **github-sts-action**.

## Repository Roles

There is one published site. `Depthmark/github-sts` is the **site repository**:
it owns `hugo.yaml`, the theme, the layouts, the navigation, the deploy
workflow, and the domain. `github-sts-helm` and `github-sts-action` are
**satellites**: each owns the words for its own component and ships them as a
content-only Hugo module that the site repository mounts.

A satellite has no `hugo.yaml`, no theme, no layouts, and no site of its own.
Its `docs/` directory is a Go module containing `content/en/` and `content/fr/`
and nothing that could render on its own. This is deliberate. One site means one
navigation, one search index, one language switcher, and one URL space, while
each component's documentation stays next to the code it describes and ships on
that component's release cycle.

| Repository | Role | Owns | Published at |
|---|---|---|---|
| `Depthmark/github-sts` | Site | Server API, configuration, trust-policy contract, OIDC validation, security model, compatibility matrix, end-to-end guides, and the site itself | The whole site |
| `Depthmark/github-sts-helm` | Satellite | Helm chart values, rendered Kubernetes resources, chart upgrade notes, OCI package installation, and chart release notes | Mounted under `/integrations/helm-chart/` |
| `Depthmark/github-sts-action` | Satellite | Action inputs and outputs, job lifecycle, Action errors, workflow usage, and Action versioning | Mounted under `/integrations/github-action/` |

Satellite documentation is mounted under **Integrations** because each satellite
is a way to consume the service, not a separate product. It is a subsection of
this site, reached through the Integrations section, and it inherits the site's
navigation, breadcrumbs, theme, and search.

## How satellite content reaches the site

The site repository imports each satellite as a Hugo module in `docs/hugo.yaml`,
mounting its per-language content into a subsection of `content/integrations/`:

```yaml
module:
  imports:
    - path: github.com/imfing/hextra
    - path: github.com/Depthmark/github-sts-action/docs
      mounts:
        - source: content/en
          target: content/integrations/github-action
          lang: en
        - source: content/fr
          target: content/integrations/github-action
          lang: fr
```

Two details are easy to get wrong:

- **`lang:` is required.** This site sets a per-language `contentDir`, so a
  `content/en/...` mount target silently produces nothing. `module.mounts.lang`
  is correct for Hugo 0.146.x and deprecated from 0.153 in favour of
  `sites.matrix`; migrate these blocks in the same change that raises
  `docs/.hugo-version` past 0.152.
- **The tag carries the `docs/` prefix.** A satellite's module lives in a
  subdirectory, so Go resolves it through a subdirectory-prefixed tag. `@v0.3.0`
  does not resolve; `@docs/v0.3.0` does.

```bash
cd docs && hugo mod get github.com/Depthmark/github-sts-action/docs@docs/v0.3.0
```

  A satellite must publish that prefixed tag itself. release-please does not
  create it from a single root package: `include-component-in-tag: false` on
  `"."` produces `vX.Y.Z` and nothing else. Either add a second package for
  `docs/` to the satellite's `release-please-config.json`, or push the tag from
  the release workflow:

```bash
git tag "docs/${VERSION}" "v${VERSION}" && git push origin "docs/${VERSION}"
```

  Without it, `hugo mod get ...@docs/vX.Y.Z` still succeeds, but Go falls back to
  a pseudo-version pinned to the commit. That is reproducible and permitted, and
  it is also unreadable: nothing in `go.mod` says which release it came from.

### Import rules

1. **Pin to a tag or a commit SHA.** Never import a branch, and never import
   `@latest`. The published site must be reproducible from `docs/go.mod` and
   `docs/go.sum` alone, and a satellite must never be able to change the
   published site by pushing to a branch.
2. **Import, do not copy.** Satellite content is never duplicated into the site
   repository. A copy is drift waiting to happen.
3. **No build-time remote fetching.** Pulling Markdown over HTTP at build time,
   embedding a satellite in an iframe, and scraping a satellite's rendered pages
   are all prohibited. The module system is the only supported mechanism: it is
   versioned, auditable, and offline-reproducible.
4. **Satellites own their words; the site owns their address.** A satellite
   chooses its own page structure. The site chooses the mount target, and
   therefore the URL.

### Cross-language anchors

A satellite page links into site pages in both languages through a single
`relref`, so it cannot know that a heading's French slug differs from its
English one. `## Error responses` becomes `#error-responses` while
`### Réponses d'erreur` becomes `#réponses-derreur`, and a link that appends
`#error-responses` to a `relref` resolves in English and silently lands at the
top of the page in French.

Any heading that is linked to by anchor from another page carries an explicit,
language-independent id, written once in English and used in both trees:

```markdown
### Réponses d'erreur {#error-responses}
```

Satellites may rely on this: an anchor that resolves in the English tree
resolves in the French tree. Adding an explicit id to a heading that already has
inbound links changes its URL, so add the id and update the referring links in
the same change. `check-links.py` verifies every fragment against the rendered
`id` attributes, in both languages, and is the reason this rule is enforceable
rather than aspirational.

Note that `{{< relref "/reference/api" >}}#error-responses` puts the anchor
outside the shortcode, where Hugo never validates it. Prefer
`{{< relref "/reference/api#error-responses" >}}`, which fails the build when
the page is missing, and leave anchor verification to `check-links.py`.

### Publishing a satellite documentation change takes two merges

1. Merge the change in the satellite repository and release it, which pushes a
   `docs/vX.Y.Z` tag.
2. Merge a change here that moves the pin with `hugo mod get`, committing
   `docs/go.mod` and `docs/go.sum`.

The site does not change until the second merge. Ordering matters: a pin bump
here before the satellite has published its tag fails the build for everyone.

To build against a satellite change before its tag exists, replace the module
with a local checkout rather than importing a branch:

```bash
make docs-check ACTION_DOCS=../github-sts-action/docs
```

## Common Structure

The site repository:

```
docs/
  content/en/, content/fr/
  layouts/
  assets/
  static/
  scripts/            validation tooling, see Validation Rules
  documentation-contract.md
  hugo.yaml
  .hugo-version       pinned Hugo, read by both workflows and the Makefile
  go.mod, go.sum      theme and satellite pins
.github/workflows/
  docs-check.yml      gates on pull_request
  deploy-github-page.yml
```

A satellite:

```
docs/
  content/en/, content/fr/
  documentation-contract.md   synchronized copy, see Synchronization
  go.mod                      module path ends in /docs
```

A satellite has no `hugo.yaml`, no `layouts/`, and no deploy workflow. If one
appears, the satellite has stopped being a satellite.

## Language Policy

- **English** is the source language for all documentation.
- **French** is the required translated language.
- English is published at the default path (no prefix).
- French is published under the `/fr/` prefix.
- Use Hugo `translationKey` front matter so the language switcher opens the equivalent page.

## Protected Terminology

The following terms must use consistent translations. The authoritative glossary lives in `docs/scripts/translate-glossary.json`.

| English | French | Notes |
|---|---|---|
| `github-sts` | `github-sts` | Never translate the project name |
| `OIDC` | `OIDC` | Never translate |
| `GitHub App` | `GitHub App` | Never translate |
| `GitHub Actions` | `GitHub Actions` | Never translate |
| `trust policy` | `politique de confiance` | |
| `audience` | `audience` | Keep English; it's an OIDC concept |
| `issuer` | `émetteur` | |
| `least privilege` | `privilège minimal` | |
| `replay` | `rejeu` | |
| `JWKS` | `JWKS` | Never translate |
| `JWT` | `JWT` | Never translate |
| `Rego` | `Rego` | Never translate |
| `bundle` | `bundle` | Keep English in Rego context |
| `token exchange` | `échange de jeton` | |
| `installation token` | `jeton d'installation` | |
| `subject` (literal claim key, e.g. `subject:` in a trust policy) | `subject` | Never translate as a YAML/JWT key; `subject` as prose may still read naturally in French |
| `subject_pattern` (literal claim key) | `subject_pattern` | Never translate |
| `audience` (literal claim key, e.g. `audience:`) | `audience` | Never translate as a YAML/JWT key |
| `issuer` (literal claim key, e.g. `issuer:`) | `issuer` | Never translate as a YAML/JWT key; `issuer` as prose translates to `émetteur` |

## Writing Style

- **Task-first:** Lead with what the user wants to accomplish.
- **Concise:** Each sentence should carry weight.
- **Active voice:** "The server validates the token" not "The token is validated by the server."
- **Security-first:** Explain the security implication of every configuration choice.
- **Stable headings:** Heading text becomes anchors. Do not rename casually.
- **Examples before references:** Show a working example before a full reference table.

## Example Rules

All documentation examples must follow these rules:

1. **Fake credentials only:** Use fictional IDs, domains, tokens (e.g., `123456`, `myorg`, `stsexample.com`, `ghs_xxxxxxxxxxxxxxxxxxxx`).
2. **Explicit audiences:** Every OIDC token request example must use `core.getIDToken('https://sts.example.com')`, never the repo URL default.
3. **Pinned versions:** Use specific tag or commit SHA (e.g., `@v0.1.0`), never `@main`.
4. **Least-privilege permissions:** Grant only the minimum permissions the example requires.
5. **Immutable identity:** Use `subject` (exact match) whenever possible, not `subject_pattern`.
6. **No organization scope** unless the current server release supports it (current: not supported).

## Validation Rules

Every documentation pull request must pass `make docs-check`, which the
`docs-check.yml` workflow runs on every pull request touching `docs/**`:

1. **Build:** Hugo Extended at the version in `docs/.hugo-version`, with
   `--panicOnWarning` and the production `baseURL`, so a green check cannot
   coexist with a failing deploy.
2. **Bilingual parity:** `docs/scripts/check-translations.py`. Page-for-page
   correspondence in both directions, `translationKey` on every page, matching
   heading counts, and a minimum French-to-English word ratio. Known drift is
   recorded in `docs/scripts/translation-baseline.json`; new drift fails.
3. **Rendered link and anchor check:** `docs/scripts/check-links.py` against
   `docs/public`. Hugo's `relref` validates the target page but not the
   fragment, so anchors are checked separately.
4. **Writing standard:** `docs/scripts/check-style.py` for the mechanical rules
   in `.agents/standards/WRITING_STANDARD.md`.

Two rules are still enforced by review rather than by a script:

5. **Secret scanning:** No real private keys, tokens, passwords, or production endpoints.
6. **Integration example checks:** Helm chart and Action versions referenced in examples match the compatibility matrix.

Satellite content is validated in the site repository, because that is the only
place it renders. A satellite cannot check its own links: half of them point at
pages that only exist once mounted. This is why the pin bump is a real merge
with a real check, not a formality.

## Release Rules

1. Update release notes (auto-generated by release-please).
2. Update the compatibility matrix in `integrations/compatibility.md`.
3. Update versioned links in integration examples.
4. Merge documentation updates with, or before, the release publication.
5. Trigger a documentation deployment after the release is available.

## Synchronization

This contract is the authoritative version in `Depthmark/github-sts/docs/documentation-contract.md`. It is copied to:

- `Depthmark/github-sts-helm/docs/documentation-contract.md`
- `Depthmark/github-sts-action/docs/documentation-contract.md`

Copies must record the source contract version and the synchronization date:

```markdown
Synchronized from: Depthmark/github-sts v{version}
Synchronized on: {date}
```

> **Re-sync required.** Version 2.0.0 changes the repository roles: the
> satellites are now content-only modules mounted into this site rather than
> separate sites. Both copies are still at 1.0.0 and describe the previous
> arrangement, including a `hugo.yaml` and a deploy workflow that satellites
> must no longer have. Re-sync both before the next satellite release.

## Changelog

### 2.0.0 (2026-08-19)

- One site, one repository. `github-sts` is the site repository; `github-sts-helm`
  and `github-sts-action` are content-only satellites with no `hugo.yaml`, no
  theme, and no deploy workflow of their own.
- Satellite content is imported as a pinned Hugo module and mounted under
  Integrations. Copying, branch imports, `@latest`, build-time remote fetching,
  iframes, and scraping are all prohibited.
- Publishing a satellite documentation change takes two merges: release the
  satellite, then move the pin here.
- Validation rules now name the four scripted gates and the workflow that runs
  them, replacing the `task docs:*` commands, which never existed in this
  repository.

### 1.0.0 (2026-08-11)

- Initial contract.
