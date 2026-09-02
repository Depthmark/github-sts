#!/usr/bin/env bash
#
# probe-token-permissions.sh — answer, against the real GitHub API, whether
# an installation access token honours a requested permission *downgrade*.
#
# The question this exists to settle: if the App installation holds
# `contents: write` and we ask for `contents: read`, does GitHub return a
# read token, or does it hand back write anyway? GitHub's docs only state
# the constraint in one direction ("cannot be granted permissions that the
# app was not granted") and never say a lower level is honoured rather than
# ignored. If it were ignored, permission narrowing in github-sts would be
# silently unenforceable, and every narrowed token would be a lie.
#
# The second thing it settles: which permissions GitHub attaches
# *implicitly*. metadata:read is expected on every token regardless of the
# ask. The divergence check in internal/github/app.go must ignore exactly
# that set and no more, so `implicitPermissions` there should be written
# from this script's output rather than from assumption.
#
# This is a read-only probe against your own App. It mints three short-lived
# tokens and prints the `permissions` object GitHub returns for each. It
# never prints a token value. The tokens are revoked on exit.
#
# Usage:
#   GITHUBSTS_PROBE_APP_ID=123456 \
#   GITHUBSTS_PROBE_KEY=/path/to/private-key.pem \
#   GITHUBSTS_PROBE_ORG=my-org \
#   tools/probe-token-permissions.sh
#
# The App must be installed on the org with contents:write and issues:write
# (or edit PROBE_PERMISSION below to match what it actually holds).

set -euo pipefail

APP_ID="${GITHUBSTS_PROBE_APP_ID:?set GITHUBSTS_PROBE_APP_ID}"
KEY_PATH="${GITHUBSTS_PROBE_KEY:?set GITHUBSTS_PROBE_KEY to the App private key PEM}"
ORG="${GITHUBSTS_PROBE_ORG:?set GITHUBSTS_PROBE_ORG}"
API_URL="${GITHUBSTS_PROBE_API_URL:-https://api.github.com}"

# The permission whose downgrade is under test. The App installation must
# hold this at write for the probe to mean anything.
PROBE_PERMISSION="${GITHUBSTS_PROBE_PERMISSION:-contents}"

require() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }
}
require curl
require jq
require openssl

[[ -r "$KEY_PATH" ]] || { echo "cannot read private key at $KEY_PATH" >&2; exit 1; }

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

app_jwt() {
  local now header payload signing_input signature
  now="$(date +%s)"
  header='{"alg":"RS256","typ":"JWT"}'
  payload="$(jq -cn --argjson iat "$((now - 60))" --argjson exp "$((now + 540))" \
    --arg iss "$APP_ID" '{iat:$iat,exp:$exp,iss:$iss}')"
  signing_input="$(printf '%s' "$header" | b64url).$(printf '%s' "$payload" | b64url)"
  signature="$(printf '%s' "$signing_input" | openssl dgst -sha256 -sign "$KEY_PATH" | b64url)"
  printf '%s.%s' "$signing_input" "$signature"
}

JWT="$(app_jwt)"

INSTALLATION="$(curl -sS -H "Authorization: Bearer $JWT" \
  -H "Accept: application/vnd.github+json" \
  "$API_URL/orgs/$ORG/installation")"

INSTALLATION_ID="$(printf '%s' "$INSTALLATION" | jq -r '.id // empty')"
if [[ -z "$INSTALLATION_ID" ]]; then
  echo "could not resolve installation for org $ORG:" >&2
  printf '%s\n' "$INSTALLATION" | jq . >&2
  exit 1
fi

echo "== installation $INSTALLATION_ID on $ORG =="
echo "granted to the installation:"
printf '%s' "$INSTALLATION" | jq '.permissions'
echo

MINTED_TOKENS=()
cleanup() {
  # Tokens last an hour; don't leave probe credentials lying around.
  for t in ${MINTED_TOKENS+"${MINTED_TOKENS[@]}"}; do
    curl -sS -o /dev/null -X DELETE -H "Authorization: Bearer $t" \
      -H "Accept: application/vnd.github+json" "$API_URL/installation/token" || true
  done
}
trap cleanup EXIT

probe() {
  local label="$1" body="$2" response granted token
  echo "== $label =="
  echo "requested: ${body:-<no permissions field>}"

  if [[ -z "$body" ]]; then
    response="$(curl -sS -X POST -H "Authorization: Bearer $JWT" \
      -H "Accept: application/vnd.github+json" \
      "$API_URL/app/installations/$INSTALLATION_ID/access_tokens")"
  else
    response="$(curl -sS -X POST -H "Authorization: Bearer $JWT" \
      -H "Accept: application/vnd.github+json" \
      -H "Content-Type: application/json" \
      -d "$body" \
      "$API_URL/app/installations/$INSTALLATION_ID/access_tokens")"
  fi

  granted="$(printf '%s' "$response" | jq '.permissions // empty')"
  if [[ -z "$granted" ]]; then
    echo "no permissions in response (request refused?):"
    printf '%s' "$response" | jq 'del(.token)'
    echo
    return
  fi

  token="$(printf '%s' "$response" | jq -r '.token // empty')"
  [[ -n "$token" ]] && MINTED_TOKENS+=("$token")

  echo "granted:"
  printf '%s' "$granted" | jq .
  echo "expires_at: $(printf '%s' "$response" | jq -r '.expires_at // "?"')"
  echo
}

# 1. Baseline: no permissions field at all. Documents the inherit-everything
#    behaviour and shows what a full grant looks like for this installation.
probe "baseline (inherit everything)" ""

# 2. THE HYPOTHESIS. Installation holds write; ask for read. If the granted
#    object comes back with "$PROBE_PERMISSION": "read", the downgrade is
#    honoured and narrowing is enforceable. If it comes back "write",
#    narrowing cannot be enforced at the GitHub layer and github-sts must
#    reject narrowed requests rather than issue an over-privileged token.
probe "downgrade $PROBE_PERMISSION write -> read" \
  "$(jq -cn --arg p "$PROBE_PERMISSION" '{permissions: {($p): "read"}}')"

# 3. Mixed levels in one request, plus a permission left out entirely, to
#    confirm per-key resolution rather than an all-or-nothing rule.
probe "mixed levels ($PROBE_PERMISSION write + issues read)" \
  "$(jq -cn --arg p "$PROBE_PERMISSION" '{permissions: {($p): "write", issues: "read"}}')"

cat <<'NOTE'
== how to read this ==
Case 2 is the answer.
  granted contents=read  -> downgrade honoured; narrowing is enforceable.
  granted contents=write -> downgrade IGNORED; stop and report. Narrowing
                            would be unenforceable upstream, and the broker
                            must reject narrowed requests instead of minting
                            a token that exceeds the ask.

Any permission appearing in a grant that was not requested (case 2 or 3) is
implicit. Reconcile that set against implicitPermissions in
internal/github/app.go — it currently lists only metadata.
NOTE
