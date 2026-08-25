# Documentation Contract

Version: 2.2.0
Last updated: 2026-08-25

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
    - path: github.com/Depthmark/github-sts-action
      mounts:
        - source: docs/content/en
          target: content/integrations/github-action
          sites:
            matrix:
              languages: [en]
        - source: docs/content/fr
          target: content/integrations/github-action
          sites:
            matrix:
              languages: [fr]
```

The module is the satellite **repository**, declared by a `go.mod` at its root,
not a module inside `docs/`. The mount reaches into `docs/content` from there.
That choice matters:

- The pin is the ordinary release tag, `@vX.Y.Z`, which release-please already
  creates. A module in a `docs/` subdirectory would need a `docs/vX.Y.Z` tag.
  release-please cannot produce one: with a single root package it emits
  `vX.Y.Z`, and its component form is `component-vX.Y.Z` with a hyphen, while Go
  requires a slash. The tag would have to be pushed by hand on every release.
- When that tag is missing, `hugo mod get …/docs@docs/vX.Y.Z` does not fail. Go
  falls back to a pseudo-version pinned to the commit, which builds correctly and
  records nothing about which release it came from. A failure mode that looks
  like success is worse than one that stops the build.
- It costs nothing. Go downloads the parent repository regardless, to determine
  whether a submodule exists there.

Satellite documentation ships with the component it documents: release v0.3.1 of
the action publishes v0.3.1 of the action's documentation. A documentation-only
fix therefore produces a component release. That is the intended trade: the
alternative buys independent versioning at the cost of hand-maintained tags.

```bash
cd docs && hugo mod get github.com/Depthmark/github-sts-action@v0.3.1
```

Two more details are easy to get wrong:

- **A per-language mount selector is required.** This site sets a per-language
  `contentDir`, so a `content/en/...` mount target silently produces nothing.
  The selector is `sites.matrix.languages`, which needs Hugo 0.153 or newer and
  replaced the `module.mounts.lang` key deprecated in that release.

  The two forms are mutually exclusive and both fail quietly on the wrong Hugo.
  On 0.146 a `sites.matrix` mount is ignored: the English tree still lands
  through the default language and every French mount silently produces nothing.
  Changing the syntax and raising `docs/.hugo-version` must therefore happen in
  one commit, never separately.
- **A satellite has exactly one `go.mod`, at its root.** Leaving one in `docs/`
  as well shadows the root module and reintroduces the subdirectory problem.

### Import rules

1. **Pin to a tag, or to a commit for an interim pin.** Never import a branch,
   and never import `@latest`. The published site must be reproducible from
   `docs/go.mod` and `docs/go.sum` alone, and a satellite must never be able to
   change the published site by pushing to a branch.

   A release tag is the normal pin. It records which release the site is
   serving, and it is the only form that survives review at a glance.

   **Interim commit pin.** When a satellite has merged a documentation change
   but has not released it, the site may pin the commit instead:

   ```bash
   cd docs && hugo mod get github.com/Depthmark/github-sts-action@main
   ```

   Go does not store the branch. It resolves the reference once and writes a
   pseudo-version naming the commit, for example
   `v0.3.1-0.20260825121720-bc7d26d4b92f`. The result is still a pin: later
   pushes to that branch do not reach the site until someone re-runs the
   command. This is what makes the interim form acceptable where a branch import
   would not be.

   It exists so that documentation can ship without forcing a release of the
   component it documents. Under a repository-root module the docs and the
   component share a version, so a documentation-only fix would otherwise
   require a release containing no change to the software. Pinning the commit
   avoids that release while keeping the build reproducible.

   Two conditions apply:

   - **A pseudo-version is a debt, not a destination.** It records a commit and
     nothing about which release the reader is seeing. Replace it with the tag
     at the satellite's next release.
   - **Never pin a commit that is not on the satellite's default branch.**
     Pinning a feature branch publishes work that was never merged, and the
     commit can disappear when the branch is deleted.
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

### Satellites link to each other through this site

A satellite may link into any page of this site, including a section owned by
another satellite. Those links are ordinary `relref` calls resolved against the
assembled site, so a satellite depends on the URLs of sections it does not own.

That makes renaming a mounted section a coordinated change, not a local one.
Moving `use-github-action` to `github-action` and `deploy-with-helm` to
`helm-chart` broke a link in the other satellite in each direction, and Hugo
reported it as `REF_NOT_FOUND` rather than silently: `relref` fails the build
when the target page is missing, and it does not follow aliases. The alias
preserves the URL for a reader typing it; it does not satisfy a `relref`.

When a mounted section is renamed:

1. Fix the references in every satellite that links to it.
2. Release each of those satellites.
3. Move all the pins here in the same change that performs the rename.

A satellite already pinned at a release that references the old path keeps
failing until it is re-released, so a rename costs one release per affected
satellite. Prefer getting mount targets right the first time. When a rename is
unavoidable, grep every satellite for the old path before starting.

### Publishing a satellite documentation change takes two merges

1. Merge the change in the satellite repository and release it, which pushes a
   release tag.
2. Merge a change here that moves the pin with `hugo mod get`, committing
   `docs/go.mod` and `docs/go.sum`.

The site does not change until the second merge. Ordering matters: a pin bump
here before the satellite has published its tag fails the build for everyone.

To build against a satellite change before its tag exists, replace the module
with a local checkout rather than importing a branch:

```bash
make docs-check ACTION_DOCS=../github-sts-action    # the repo root, not docs/
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
go.mod                        module path is the repository, no dependencies
docs/
  content/en/, content/fr/
  documentation-contract.md   synchronized copy, see Synchronization
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

### 2.2.0 (2026-08-25)

- Import rules describe the interim commit pin: a satellite whose documentation
  has merged but not released may be pinned by commit, so a documentation change
  does not force a release of the component. The pin is still reproducible
  because Go resolves the reference once and records the commit rather than the
  branch. It must be replaced by a tag at the satellite's next release, and the
  commit must be on the default branch.

### 2.1.0 (2026-08-20)

- Satellite modules are declared at the repository root rather than in `docs/`,
  so the pin is the release tag release-please already creates. This removes the
  hand-maintained `docs/vX.Y.Z` tag and the pseudo-version fallback that
  silently replaced it when it was missing.
- Documented that satellites link to each other's mounted sections, which makes
  renaming a mount target a coordinated release.
- Documented the cross-language anchor rule.
- Mounts use `sites.matrix.languages` instead of the deprecated
  `module.mounts.lang`, and `docs/.hugo-version` moves to 0.164.0 in the same
  commit. The two are a single atomic change: the old key warns on new Hugo and
  the new key silently drops the French mounts on old Hugo.

### 2.0.0 (2026-08-19)

- One site, one repository. `github-sts` is the site repository; `github-sts-helm`
  and `github-sts-action` are content-only satellites with no `hugo.yaml`, no
  theme, and no deploy workflow of their own.
- Satellites may link to each other's mounted sections, which makes renaming a
  mount target a coordinated release across every satellite that references it.
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
