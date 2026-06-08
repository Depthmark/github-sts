.PHONY: build test test-race test-oci-cosign-local lint coverage vuln-check clean docker ci act act-lint act-test act-build validate-examples

SCHEMA       ?= internal/policy/yaml/schema_v1.json
EXAMPLES_DIR ?= config/examples

# Build all packages
build:
	go build ./...

# Run all tests
test:
	go test ./...

# Run tests with race detector
test-race:
	go test -race ./...

# Run local OCI/cosign integration test using a throwaway Docker registry.
# Requires docker, opa, and go. Uses cosign directly when installed, otherwise
# runs a pinned cosign CLI via go run. Uses a cosign key pair so it can run
# locally without a Fulcio/OIDC keyless signing flow.
test-oci-cosign-local:
	tools/local-oci-cosign-test.sh

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
	rm -rf bin/ coverage.out coverage.html

# Validate trust-policy examples against the v1 JSON Schema. Catches drift
# between the TrustPolicy struct and the schema, and rejects new examples
# that don't conform.
validate-examples:
	@command -v check-jsonschema >/dev/null 2>&1 || { echo "install: pipx install check-jsonschema"; exit 1; }
	check-jsonschema --schemafile $(SCHEMA) $(EXAMPLES_DIR)/*.sts.yaml

# Run all checks (CI)
ci: lint test-race vuln-check build bin/github-sts validate-examples

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
