.PHONY: build test test-race test-rego lint coverage vuln-check clean docker \
        ci act act-actions hooks validate-examples validate-repository-policies \
        docs-serve docs-build docs-check docs-links docs-style docs-translate \
        docs-hugo-version docs-satellites docs-schema check-github-permissions

SCHEMA       ?= internal/policy/yaml/schema_v1.json
# Where the published copy of the schema is staged for the documentation site.
# The path under docs/static/ becomes the public URL, so it must match the
# schema's own $id. Staged at build time and gitignored: one file in git means
# the published schema cannot drift from the one CI validates against.
SCHEMA_SITE_DIR ?= docs/static/schemas/sts/v1
EXAMPLES_DIR ?= config/examples
REGO_DIR     ?= policies
REPOSITORY_POLICIES ?= $(wildcard .github/sts/*/*.sts.yaml)
HUGO ?= hugo
HUGO_SOURCE ?= docs
# Pinned in docs/.hugo-version and read by the docs workflows, so a local
# build and CI agree. --panicOnWarning turns a version skew into a failed
# deploy, so the mismatch is worth surfacing early.
HUGO_VERSION := $(shell cat docs/.hugo-version 2>/dev/null)

# Satellite documentation is imported, not copied, and pinned to a release tag.
# To build against a local checkout of a satellite before its tag exists, or to
# test unreleased edits, point these at that repository's ROOT:
#
#   make docs-check ACTION_DOCS=../github-sts-action
#   make docs-check HELM_DOCS=../github-sts-helm
#   make docs-check ACTION_DOCS=... HELM_DOCS=...     (both at once)
#
# The Hugo module is the satellite repository itself, not its docs/ directory,
# so these take the repo root. Pointing one at .../docs would mount nothing,
# silently; docs-satellites checks for that below.
#
# Never commit a branch import to docs/go.mod; see documentation-contract.md.
ACTION_DOCS ?=
HELM_DOCS ?=

ACTION_MODULE := github.com/Depthmark/github-sts-action
HELM_MODULE   := github.com/Depthmark/github-sts-helm

# Each satellite with a local checkout contributes one "module -> path" pair and
# is exempted from the pin guard. Hugo takes the pairs comma separated.
SATELLITE_REPLACEMENTS :=
SATELLITE_REPLACED :=
SATELLITE_CHECKOUTS :=
ifneq ($(strip $(ACTION_DOCS)),)
SATELLITE_REPLACEMENTS := $(SATELLITE_REPLACEMENTS),$(ACTION_MODULE) -> $(abspath $(ACTION_DOCS))
SATELLITE_REPLACED := $(SATELLITE_REPLACED) $(ACTION_MODULE)
SATELLITE_CHECKOUTS := $(SATELLITE_CHECKOUTS) $(ACTION_MODULE):$(abspath $(ACTION_DOCS))
endif
ifneq ($(strip $(HELM_DOCS)),)
SATELLITE_REPLACEMENTS := $(SATELLITE_REPLACEMENTS),$(HELM_MODULE) -> $(abspath $(HELM_DOCS))
SATELLITE_REPLACED := $(SATELLITE_REPLACED) $(HELM_MODULE)
SATELLITE_CHECKOUTS := $(SATELLITE_CHECKOUTS) $(HELM_MODULE):$(abspath $(HELM_DOCS))
endif

ifneq ($(strip $(SATELLITE_REPLACEMENTS)),)
HUGO_REPLACE := HUGO_MODULE_REPLACEMENTS="$(shell printf '%s' '$(SATELLITE_REPLACEMENTS)' | sed 's/^,//')"
else
HUGO_REPLACE :=
endif

# The guard always runs. It exempts modules that are pinned in go.mod and
# modules that have a local replacement, so it is silent unless an import is
# genuinely unresolvable or a supplied checkout is wrong.
SATELLITE_GUARD := docs-satellites

# Build all packages
build:
	go build ./...

# Run all tests
test:
	go test ./...

# Run tests with race detector
test-race:
	go test -race ./...

# Format-check, compile, and test the enterprise Rego contract.
test-rego:
	@command -v opa >/dev/null 2>&1 || { echo "install OPA: https://www.openpolicyagent.org/docs/latest/#running-opa"; exit 1; }
	opa fmt --fail $(REGO_DIR)/*.rego >/dev/null
	opa check --strict $(REGO_DIR)
	opa test $(REGO_DIR)

# The cosign format compatibility matrix needs Docker, a throwaway registry, and
# two pinned cosign binaries, so it lives outside this repository in
# Depthmark-Lab/test-github-sts/scripts/local-oci-cosign-test.sh. The Go side is
# TestOCILoader_CosignCompatibility, which skips unless that harness supplies
# GITHUBSTS_OCI_COMPAT_REGISTRY and GITHUBSTS_OCI_COMPAT_PUBLIC_KEY.

# Run tests with coverage
coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out
	@echo "---"
	@echo "HTML report: go tool cover -html=coverage.out -o coverage.html"

# Run linter
lint:
	golangci-lint run ./...

# Run vulnerability check
vuln-check:
	govulncheck ./...

# Build production binary
bin/github-sts:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/github-sts ./cmd/github-sts

# Build the policy release/GitOps revision gate.
bin/github-sts-bundle:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/github-sts-bundle ./cmd/github-sts-bundle

# Build Docker image
docker:
	docker build -t github-sts:local .

# Clean build artifacts
clean:
	rm -rf bin/ coverage.out coverage.html docs/public/

# Validate trust-policy examples against the v1 JSON Schema. Catches drift
# between the TrustPolicy struct and the schema, and rejects new examples
# that don't conform.
validate-examples:
	@command -v check-jsonschema >/dev/null 2>&1 || { echo "install: pipx install check-jsonschema"; exit 1; }
	check-jsonschema --schemafile $(SCHEMA) $(EXAMPLES_DIR)/*.sts.yaml

# Validate repository-owned policies separately from synthetic examples.
validate-repository-policies:
	@command -v check-jsonschema >/dev/null 2>&1 || { echo "install: pipx install check-jsonschema"; exit 1; }
	check-jsonschema --schemafile $(SCHEMA) $(REPOSITORY_POLICIES)

# Diff the permission table in internal/policy against GitHub's published
# OpenAPI description. Excluded from `ci` on purpose: it reaches the network,
# and GitHub adding a permission should open a pull request rather than turn an
# unrelated build red. Run it on a schedule, or before a release.
check-github-permissions:
	go test -tags githubspec -count=1 -v ./internal/policy/ -run 'TestGitHubSpec|TestValidPermissionLevelsMatchGitHubSpec'

# Run all checks (CI)
ci: lint test-race test-rego vuln-check build bin/github-sts validate-examples

# Run all CI jobs locally with act
act:
	act pull_request --workflows .github/workflows/ci.yml

# Validate GitHub Actions workflows locally with the shared CI workflow
act-actions:
	act pull_request --workflows .github/workflows/ci-actions.yml

# Enable the repository's versioned Git hooks.
# Installs .githooks/pre-push, which runs `make docs-check` before a push that
# touches docs/. It is local convenience only: the enforcement boundary is
# .github/workflows/docs-check.yml, which a hook cannot replace because hooks
# are opt-in, skippable with --no-verify, and absent on forks.
hooks:
	git config core.hooksPath .githooks
	@echo "hooks enabled: $$(ls .githooks | tr '\n' ' ')"

# --- Documentation targets ---

# Satellite modules are imported by docs/hugo.yaml but resolved through
# docs/go.mod. Until a satellite has published its docs/vX.Y.Z tag there is no
# require entry to resolve, and Hugo fails with a raw "go get" error that does
# not say what to do. Catch that case and say it.
.PHONY: docs-satellites
docs-satellites:
	@for pair in $(SATELLITE_CHECKOUTS); do \
	  mod="$${pair%%:*}"; dir="$${pair#*:}"; \
	  if [ ! -f "$$dir/go.mod" ] || ! grep -q "^module $$mod$$" "$$dir/go.mod" 2>/dev/null; then \
	    echo "error: $$dir does not look like a checkout of $$mod."; \
	    echo ""; \
	    echo "  Point this at the repository ROOT, not its docs/ directory."; \
	    echo "  The Hugo module is the repository; the mount reaches into docs/content."; \
	    echo "  Expected $$dir/go.mod to declare: module $$mod"; \
	    exit 1; \
	  fi; \
	done
	@for m in $$(grep -oE 'path: (github\.com/Depthmark/[a-z-]+)' docs/hugo.yaml | awk '{print $$2}' | sort -u); do \
	  case " $(SATELLITE_REPLACED) " in *" $$m "*) continue;; esac; \
	  if grep -q "$$m " docs/go.mod; then continue; fi; \
	  case "$$m" in \
	    *github-sts-helm*) var=HELM_DOCS; repo=github-sts-helm;; \
	    *) var=ACTION_DOCS; repo=github-sts-action;; \
	  esac; \
	  dir=""; \
	  for c in "../$$repo" "../../$$repo" "../../$$repo-worktree"/*/ "../../../$$repo"; do \
	    if [ -f "$$c/go.mod" ] && grep -q "^module $$m$$" "$$c/go.mod" 2>/dev/null; then \
	      dir="$$c"; break; \
	    fi; \
	  done; \
	  if [ -z "$$dir" ]; then dir="../$$repo"; fi; \
	  echo "error: docs/hugo.yaml imports $$m but docs/go.mod has no pin for it."; \
	  echo ""; \
	  echo "  That satellite has not published a release tag containing its root"; \
	  echo "  go.mod yet. Until it does, build against a local checkout:"; \
	  echo ""; \
	  echo "    make $(MAKECMDGOALS) $$var=$$dir"; \
	  echo ""; \
	  echo "  Once the tag exists, pin it and commit go.mod and go.sum:"; \
	  echo ""; \
	  echo "    cd docs && hugo mod get $$m@vX.Y.Z"; \
	  echo ""; \
	  echo "  Never import a branch. See docs/documentation-contract.md."; \
	  exit 1; \
	done

# Warn when the local Hugo differs from the version CI builds with.
.PHONY: docs-hugo-version
docs-hugo-version:
	@local="$$($(HUGO) version | sed -n 's/^hugo v\([0-9.]*\).*/\1/p')"; \
	if [ -n "$(HUGO_VERSION)" ] && [ "$$local" != "$(HUGO_VERSION)" ]; then \
	  echo "warning: local Hugo $$local, CI builds with $(HUGO_VERSION) (docs/.hugo-version)"; \
	fi

# Stage the trust-policy schema into the site's static tree so Hugo publishes
# it at https://depthmark.github.io/github-sts/schemas/sts/v1/trust-policy.json.
# Consumers point their editor's yaml-language-server at that URL, so the path
# is a public contract: see the stability note in the schema's description.
docs-schema:
	@mkdir -p $(SCHEMA_SITE_DIR)
	@cp $(SCHEMA) $(SCHEMA_SITE_DIR)/trust-policy.json

# Serve the documentation site locally
docs-serve: docs-hugo-version docs-schema $(SATELLITE_GUARD)
	$(HUGO_REPLACE) $(HUGO) server --source $(HUGO_SOURCE) --buildDrafts

# Build the documentation site for production
docs-build: docs-hugo-version docs-schema $(SATELLITE_GUARD)
	$(HUGO_REPLACE) $(HUGO) --source $(HUGO_SOURCE) --gc --minify --panicOnWarning \
		--baseURL https://depthmark.github.io/github-sts/

# Every gate the docs-check workflow runs, in the same order. Each one exits
# non-zero on failure: this target is the contract, not a report.
docs-check: docs-build
	python3 docs/scripts/check-translations.py
	python3 docs/scripts/check-links.py --base docs/public --base-path /github-sts
	python3 docs/scripts/check-style.py

# Validate links and anchors in the generated site
docs-links: docs-build
	python3 docs/scripts/check-links.py --base docs/public --base-path /github-sts

# Check the mechanical rules in .agents/standards/WRITING_STANDARD.md
docs-style:
	python3 docs/scripts/check-style.py

# Run the translation tool locally. The tool itself is not in the repository:
# French translation is a review task, not a generation step.
docs-translate:
	@test -f docs/scripts/translate-docs.py || { \
	  echo "docs/scripts/translate-docs.py is not in this repository."; \
	  echo "Translate by hand and verify with: make docs-check"; \
	  exit 1; }
	python3 docs/scripts/translate-docs.py
