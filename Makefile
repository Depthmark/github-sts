.PHONY: build test test-race test-rego test-oci-cosign-local lint coverage vuln-check clean docker ci act act-lint act-test act-build validate-examples validate-repository-policies

SCHEMA       ?= internal/policy/yaml/schema_v1.json
EXAMPLES_DIR ?= config/examples
REGO_DIR     ?= policies
REPOSITORY_POLICIES ?= $(wildcard .github/sts/*/*.sts.yaml)

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

# Build the policy release/GitOps revision gate.
bin/github-sts-bundle:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/github-sts-bundle ./cmd/github-sts-bundle

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

# Validate repository-owned policies separately from synthetic examples.
validate-repository-policies:
	@command -v check-jsonschema >/dev/null 2>&1 || { echo "install: pipx install check-jsonschema"; exit 1; }
	check-jsonschema --schemafile $(SCHEMA) $(REPOSITORY_POLICIES)

# Run all checks (CI)
ci: lint test-race test-rego vuln-check build bin/github-sts validate-examples

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
