.PHONY: build test test-race lint coverage vuln-check clean docker ci act act-lint act-test act-build \
        docs-serve docs-build docs-check docs-links docs-translate

HUGO ?= hugo
HUGO_SOURCE ?= docs

# Build all packages
build:
	go build ./...

# Run all tests
test:
	go test ./...

# Run tests with race detector
test-race:
	go test -race ./...

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

# Build Docker image
docker:
	docker build -t github-sts:local .

# Clean build artifacts
clean:
	rm -rf bin/ coverage.out coverage.html docs/public/

# Run all checks (CI)
ci: lint test-race vuln-check build bin/github-sts

# Run all CI jobs locally with act
act:
	act pull_request --workflows .github/workflows/ci.yml

# Run individual CI jobs locally with act
act-lint:
	act pull_request --workflows .github/workflows/ci.yml --job lint

act-test:
	act pull_request --workflows .github/workflows/ci.yml --job test

act-build:
	act pull_request --workflows .github/workflows/ci.yml --job build

# --- Documentation targets ---

# Serve the documentation site locally
docs-serve:
	$(HUGO) server --source $(HUGO_SOURCE) --buildDrafts

# Build the documentation site for production
docs-build:
	$(HUGO) --source $(HUGO_SOURCE) --gc --minify --panicOnWarning \
		--baseURL https://depthmark.github.io/github-sts/

# Validate documentation content, translation parity, and build
docs-check:
	python3 docs/scripts/check-translations.py || true
	$(HUGO) --source $(HUGO_SOURCE) --gc --minify --panicOnWarning \
		--baseURL https://depthmark.github.io/github-sts/
	python3 docs/scripts/check-links.py --base docs/public --base-path /github-sts

# Validate links in the generated site
docs-links:
	$(HUGO) --source $(HUGO_SOURCE) --gc --minify --panicOnWarning \
		--baseURL https://depthmark.github.io/github-sts/
	python3 docs/scripts/check-links.py --base docs/public --base-path /github-sts

# Run the translation tool locally
docs-translate:
	python3 docs/scripts/translate-docs.py
