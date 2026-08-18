#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="${GITHUBSTS_LOCAL_OCI_WORKDIR:-$(mktemp -d)}"
REGISTRY_PORT="${GITHUBSTS_LOCAL_OCI_REGISTRY_PORT:-5000}"
REGISTRY_NAME="github-sts-oci-registry-$REGISTRY_PORT"
REF="oci://localhost:${REGISTRY_PORT}/github-sts/policy:local"
IMAGE_REF="localhost:${REGISTRY_PORT}/github-sts/policy:local"
COSIGN_PASSWORD_VALUE="${COSIGN_PASSWORD:-github-sts-local}"

cleanup() {
  if [[ "${GITHUBSTS_LOCAL_OCI_KEEP_REGISTRY:-}" != "true" ]]; then
    docker rm -f "$REGISTRY_NAME" >/dev/null 2>&1 || true
  fi
  if [[ "${GITHUBSTS_LOCAL_OCI_KEEP_WORKDIR:-}" != "true" ]]; then
    rm -rf "$WORK_DIR"
  else
    printf 'kept workdir: %s\n' "$WORK_DIR"
  fi
}
trap cleanup EXIT

require() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'missing required command: %s\n' "$1" >&2
    exit 1
  }
}

require docker
require go
require opa

cosign_cmd() {
  if command -v cosign >/dev/null 2>&1; then
    cosign "$@"
  else
    go run github.com/sigstore/cosign/v2/cmd/cosign@v2.6.3 "$@"
  fi
}

cd "$ROOT_DIR"
mkdir -p "$WORK_DIR/policy"

cat >"$WORK_DIR/policy/decision.rego" <<'REGO'
package sts.local

default decision := {"allow": true, "reasons": []}
REGO

opa build -b "$WORK_DIR/policy" -o "$WORK_DIR/bundle.tar.gz"

docker rm -f "$REGISTRY_NAME" >/dev/null 2>&1 || true
docker run -d --name "$REGISTRY_NAME" -p "${REGISTRY_PORT}:5000" registry:2 >/dev/null
sleep 1

go run github.com/google/go-containerregistry/cmd/crane@v0.21.6 append \
  --insecure \
  --oci-empty-base \
  --new_layer "$WORK_DIR/bundle.tar.gz" \
  --new_tag "$IMAGE_REF" >/dev/null

COSIGN_PASSWORD="$COSIGN_PASSWORD_VALUE" cosign_cmd generate-key-pair --output-key-prefix "$WORK_DIR/cosign" >/dev/null
COSIGN_PASSWORD="$COSIGN_PASSWORD_VALUE" cosign_cmd sign \
  --key "$WORK_DIR/cosign.key" \
  --tlog-upload=false \
  --allow-insecure-registry \
  --yes \
  "$IMAGE_REF" >/dev/null

GITHUBSTS_OCI_TEST_REF="$REF" \
GITHUBSTS_OCI_TEST_PUBLIC_KEY_REF="$WORK_DIR/cosign.pub" \
GITHUBSTS_OCI_TEST_IGNORE_TLOG=true \
  go test ./internal/bundle -run TestOCILoader_LocalRegistrySignedBundle -count=1 -v

if [[ "${GITHUBSTS_LOCAL_OCI_KEEP_REGISTRY:-}" == "true" && "${GITHUBSTS_LOCAL_OCI_KEEP_WORKDIR:-}" == "true" ]]; then
  cat <<EOF

Local OCI/cosign test passed and fixture was kept.

Configure github-sts with:
  ref: $REF
  cosign:
    public_key_ref: $WORK_DIR/cosign.pub
    ignore_tlog: true
EOF
else
  cat <<'EOF'

Local OCI/cosign test passed.

To keep the registry and public key for manual github-sts testing, rerun with:
  GITHUBSTS_LOCAL_OCI_KEEP_REGISTRY=true GITHUBSTS_LOCAL_OCI_KEEP_WORKDIR=true tools/local-oci-cosign-test.sh
EOF
fi
