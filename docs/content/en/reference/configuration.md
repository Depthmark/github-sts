---
title: Configuration
description: YAML configuration structure, default values, and complete reference.
weight: 2
translationKey: configuration
---

github-sts is configured through a YAML file, environment variables, or both. Environment variables override values from YAML, making YAML the source of truth for defaults and env vars the right place for secrets and per-environment overrides.

## YAML configuration

Point github-sts at a config file with `GITHUBSTS_CONFIG_PATH`:

```bash
export GITHUBSTS_CONFIG_PATH=/etc/github-sts/config.yaml
```

See [`config/github-sts.example.yaml`](https://github.com/Depthmark/github-sts/blob/main/config/github-sts.example.yaml) in the repo for a complete example; ready-to-use trust-policy templates live in [`config/examples/`](https://github.com/Depthmark/github-sts/tree/main/config/examples).

A minimal local-development config with YAML-only authorization:

```yaml
bundle_enforcement: optional
bundles: []

server:
  port: 8080
  log_level: info

oidc:
  allowed_issuers:
    - https://token.actions.githubusercontent.com
  required_audience: https://sts.example.com
  require_immutable_subject_claims: true

apps:
  default:
    app_id: 123456
    private_key_path: /etc/github-sts/keys/default.pem
    org_policy_repo: .github
    policy_resolution: org_first
```

Valid log levels are lowercase `debug | info | warn | error`. `oidc.allowed_issuers` must contain at least one issuer; an empty list is a validation error. Top-level `bundle_enforcement` is also mandatory. See [Enterprise Rego bundles](#enterprise-rego-bundles) below. The explicit optional/no-bundle posture above emits a startup warning and observable health, metric, and audit signals; production deployments should use required mode.

For production, deploy github-sts with the Helm chart rather than hand-managing this file. See [Deploy with Helm]({{< relref "/integrations/deploy-with-helm" >}}).

## App pools (multi-instance rate-limit rotation)

A logical app name (`apps.<name>`) can be backed by a single GitHub App (`app_id` / `private_key` / `private_key_path`, as above) or by a pool of several physical GitHub Apps under `instances:`. Each instance has its own GitHub App credentials and therefore its own independent GitHub primary rate-limit bucket, so a pooled app's effective ceiling on `/sts/exchange` traffic scales with the number of instances. (This "instance" is a physical GitHub App, unrelated to a github-sts server replica; see [Architecture]({{< relref "/concepts/architecture#app-pools-and-failover" >}}).) Callers only ever see the logical app name in `?app=`; which instance served a given request is internal, and shows up only in the `instance` label on metrics and in the audit log (see [Metrics]({{< relref "/reference/metrics#app-pool-metrics" >}})).

```yaml
apps:
  checkout:
    org_policy_repo: ".github"
    instances:
      - name: checkout-1          # optional; defaults to app_id if omitted
        app_id: 111111
        private_key_path: "/etc/github-sts/keys/checkout-1.pem"
      - name: checkout-2
        app_id: 222222
        private_key_path: "/etc/github-sts/keys/checkout-2.pem"
      - name: checkout-3
        app_id: 333333
        private_key_path: "/etc/github-sts/keys/checkout-3.pem"
    rotation:
      strategy: round_robin        # round_robin (default) | rate_limit_aware
      min_remaining_pct: 5         # rate_limit_aware only
      max_attempts: 3              # bound failover fan-out per request
```

By default, github-sts round-robins across a pool's instances (a per-request cursor, so retries within one request walk consecutive members rather than re-randomizing), skips any instance the reachability prober currently reports down, and fails over to the next instance when the one it tried returns a retryable error. Retryable means a network/timeout error, a 5xx response, or a 403 that carries a rate-limit signal (`Retry-After` or `X-RateLimit-Remaining: 0`); a 422 (the requested permissions or repositories exceed what that installation grants) or any other 4xx is not retried, since trying a different credential cannot fix a permissions mismatch. `rotation.max_attempts` bounds how many instances one request will try (default: pool size, capped at 3).

Rules:

- `instances` and the flat `app_id` / `private_key` / `private_key_path` fields are mutually exclusive on one app. A flat-form app is treated as a pool of one.
- `rotation` is only meaningful on a pooled app (`instances` set): setting it on a flat-form app is a validation error, since it would otherwise be YAML that silently did nothing.
- Every instance needs `app_id` and exactly one of `private_key` / `private_key_path`.
- `app_id` must be unique **within** one app's pool. The same `app_id` reused across two different logical apps' pools is allowed (they already share a rate-limit bucket by construction) but logs a startup warning, since it's more often a copy-paste mistake than an intentional setup.
- `name` is optional and defaults to `app_id` (stringified). Because it becomes a Prometheus label value, it is limited to 100 characters from `[a-zA-Z0-9._/-]`.
- `rotation.strategy` is `round_robin` (default) or `rate_limit_aware`. **`rate_limit_aware` is accepted today but not yet implemented**: a pool configured with it behaves identically to `round_robin`, and github-sts logs a startup warning to that effect. It's reserved for a proactive-skip strategy that ranks instances by their last-observed remaining rate-limit percentage before making a request, rather than only reacting to a live failure.
- `rotation.min_remaining_pct` (range `[0, 100)`) only applies to `rate_limit_aware` and currently has no effect for the reason above.
- `rotation.max_attempts` defaults to `min(len(instances), 3)` when unset or `0`.

**Operational requirement:** every instance in a pool must be installed with identical permissions and repository access. github-sts treats pool members as interchangeable; it does not currently verify that they actually are, so a misconfigured instance surfaces only as an intermittent 422 or reachability failure on whichever fraction of requests happen to land on it.

## Native TLS and mTLS

github-sts can serve HTTPS directly, but it does not manage certificate lifecycles. TLS is **implicitly enabled** when you provide both a certificate and a key; provide a client CA bundle to require and verify client certificates (mTLS):

```yaml
server:
  port: 8443
  tls:
    cert_file: /etc/github-sts/tls/tls.crt
    key_file: /etc/github-sts/tls/tls.key
    # Optional: enable mTLS by trusting a client CA bundle.
    # client_ca_file: /etc/github-sts/tls/client-ca.crt

    # Optional: enforce TLS 1.3 only (default: "1.2", meaning TLS 1.2 and above).
    # min_version: "1.3"

    # Optional: restrict to specific TLS 1.2 cipher suites (IANA names).
    # Omit to use Go's defaults. Cannot be set when min_version is "1.3".
    # cipher_suites:
    #   - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    #   - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    #   - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256

    # Optional: poll cert/key files on an interval and reload them when changed,
    # enabling zero-downtime certificate rotation. "0" disables polling (default).
    # Without this, cert rotation requires a process restart.
    # reload_interval: 1h
```

Rules:

- `cert_file` and `key_file` must be set together. Setting one without the other is a validation error.
- `client_ca_file` requires `cert_file` and `key_file`.
- `min_version` accepts `"1.2"` (default) or `"1.3"`. Minimum TLS version is TLS 1.2 when unset.
- `cipher_suites` accepts IANA cipher suite names. Only the non-insecure suites from Go's standard library are valid; unknown or weak names are a validation error. Setting cipher suites together with `min_version: "1.3"` is also a validation error: TLS 1.3 cipher suite selection is not configurable.
- `reload_interval` triggers interval-based polling of the cert and key files. When the files change, they are reloaded in-place without restarting the process. Requires `cert_file` and `key_file`.
- Client verification uses `RequireAndVerifyClientCert` when `client_ca_file` is set.

The recommended deployment model is to terminate TLS at the platform ingress/Gateway when available, and use native TLS for standalone deployments or when re-encrypting Gateway→backend traffic (e.g. Gateway API `BackendTLSPolicy`). See [Security Model]({{< relref "/concepts/security-model" >}}) for the trust-boundary guidance.

## Trust policies

Trust policies are YAML files stored **in the target repository** that define which OIDC identities can request tokens and with what permissions.

**Location:** `.github/sts/{app_name}/{identity}.sts.yaml`

The base path is configurable via `GITHUBSTS_POLICY_BASE_PATH` (default `.github/sts`).

See the [Trust Policies]({{< relref "/concepts/trust-policies" >}}) guide for the full policy schema, examples, and security guidance.

## Enterprise Rego bundles

Top-level `bundle_enforcement` is mandatory and accepts exactly `required` or
`optional`. Omission fails startup, including when `bundles` is empty. Set
`GITHUBSTS_BUNDLE_ENFORCEMENT` to override the YAML value.

Enterprise bundles run after the target trust policy allows and before the
GitHub token mint. An evaluated deny wins across the mandatory baseline and all
applicable additive bundles.

### Required production mode

Required mode needs exactly one globally applicable baseline, represented by
`apps: []`. Every configured bundle in required mode must be an OCI reference
pinned exactly to `@sha256:<64 lowercase hex>` and must use cosign keyless or
public-key verification. It must also declare the signed revision expected in
that digest. The global baseline must use `fail_mode: closed`.

```yaml
bundle_enforcement: required

bundles:
  - name: enterprise-baseline
    apps: []
    # Placeholder digest: replace it with the promoted bundle digest.
    ref: oci://ghcr.io/depthmark/github-sts-policy@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    expected_policy_revision: "42"
    poll_interval: 5m
    max_staleness: 10m
    fail_mode: closed
    cosign:
      certificate_identity_regexp: '^https://github\.com/Depthmark/github-sts-policy/\.github/workflows/release\.yml@refs/heads/main$'
      certificate_oidc_issuer: https://token.actions.githubusercontent.com
```

An app-scoped bundle has a nonempty list such as `apps: [release]`. It is
additive: the global baseline still evaluates for that app, and every applicable
bundle must allow. Required-mode pinning and verification rules apply to these
additive bundles too, including `expected_policy_revision`.

`expected_policy_revision` is a quoted positive base-10 `uint64` string. Zero,
signs, whitespace, leading zeroes, non-digits, and overflow are rejected. The
bundle must be built with the same authoritative OPA manifest revision:

```bash
opa build --revision 42 -b policy -o bundle.tar.gz
```

The cosign signature covers the OCI artifact containing `.manifest`. The broker
compares that manifest revision with `expected_policy_revision` before swapping
the runtime snapshot. A mismatch or missing revision fails initial installation;
on reload, the previous engine, digest, and revision remain active.

The mandatory baseline exposes the fixed documents
`data.sts.enterprise.v1.decision` and
`data.sts.enterprise.v1.metadata`. Metadata must be an object with:

- `contract_version: v1`
- `policy_revision` exactly matching the canonical `.manifest.revision`
- A `controls` array containing `immutable_identity` and `permission_boundary`
- An `admission` object containing a known-good `app`, `identity`, exact
  `source` and `target` owner/repository ID pairs, and a nonempty bounded
  `permissions` object

Before installing a baseline candidate, the broker requires the declared
admission context to allow, then independently mutates it for malformed-input,
missing-identity, unknown-source, and unknown-permission probes. Every negative
probe must produce an explicit deny. A missing or malformed fixed document,
invalid metadata, failed probe, pull/signature failure, or compile failure
prevents initial installation; a failed reload leaves the previously admitted
bundle in place.

The exchange input includes canonical `source_identity` and `target_identity`,
the typed `yaml_policy.github` relationship, exact requested permissions,
`requested.repository_ids`, and `requested.organization_wide`. The engine
overwrites `authorization.cross_org_exceptions` with only active records that
passed Go admission; callers and Rego modules cannot add records there.

Cross-org exception admission rejects unknown/missing fields, malformed IDs or
permissions, duplicate contexts, identical owner/approver identities, future
creation, expired records, and lifetimes over 30 days. Expired records are
filtered at evaluation time even if bundle refresh fails.

`cross_org_exceptions` is a field on the enterprise bundle's own data
document (`data.sts.enterprise_config.v1`, built into the OCI bundle
alongside the Rego, not something a caller passes at request time). A full
document, the shape of
[`policies/example_data.json`](https://github.com/Depthmark/github-sts/blob/main/policies/example_data.json)
used by the enterprise baseline's conformance tests, looks like this:

```json
{
  "sts": {
    "enterprise_config": {
      "v1": {
        "contract_version": "v1",
        "approved_source_owner_ids": {"123456": true, "9001": true},
        "approved_target_owner_ids": {"123456": true},
        "apps": {
          "default": {
            "permission_ceiling": {"contents": "write", "deployments": "write", "statuses": "write"},
            "targets": {
              "123456": {
                "repositories": {
                  "456789": {
                    "permission_ceiling": {"contents": "write", "deployments": "write", "statuses": "write"},
                    "identities": {
                      "deploy": {"permission_ceiling": {"contents": "write", "deployments": "write", "statuses": "write"}}
                    }
                  }
                }
              }
            }
          }
        },
        "cross_org_exceptions": [
          {
            "exception_id": "xorg-deploy-2026-08",
            "rule_id": "sts.relationship.cross_org",
            "source": {"owner_id": "9001", "repository_id": "9002"},
            "target": {"owner_id": "123456", "repository_id": "456789"},
            "app": "default",
            "identity": "deploy",
            "permission_ceiling": {"contents": "read", "deployments": "write", "statuses": "write"},
            "owner": "platform@example.com",
            "approved_by": "security@example.com",
            "reason": "org-a deploy workflow publishes releases into org-b/repo-b",
            "created_at": "2026-08-01T00:00:00Z",
            "expires_at": "2026-08-20T00:00:00Z"
          }
        ],
        "org_wide_grants": []
      }
    }
  }
}
```

Every source owner ID and target owner ID that appears anywhere in
`cross_org_exceptions` must also be listed (`true`) in
`approved_source_owner_ids` / `approved_target_owner_ids`, or the enterprise
baseline denies with `sts.context.unknown` before it even reaches the
cross-org rule. `org_wide_grants` must stay an empty array. See
[Organization-level scope]({{< relref "/concepts/trust-policies#organization-level-scope" >}}):
the broker rejects it non-empty at startup until organization-wide grants are
covered by mandatory enterprise policy. This data document is authored and
reviewed by whoever owns the enterprise policy bundle (typically a
platform/security team), built into the signed OCI bundle, and is the
"organization level" of authorization: individual repo trust policies cannot
grant cross-organization access on their own once `bundle_enforcement:
required` is in effect.

### Explicit optional development example

Optional mode does not require enterprise-policy participation. In this
no-bundle development form, exchanges are authorized only by YAML trust
policies:

```yaml
bundle_enforcement: optional
bundles: []
```

Optional mode may use a mutable OCI tag only with an explicit opt-in:

```yaml
bundle_enforcement: optional

bundles:
  - name: local-policy
    apps: []
    ref: oci://localhost:5000/github-sts-policy:dev
    allow_mutable_ref: true
    cosign:
      skip_verification: true
```

`cosign.skip_verification: true` and `file:///...` refs are for optional local
development only and are rejected in required mode. Digest-pinned optional OCI
refs must not set `allow_mutable_ref`; mutable tags must set it to `true`.
Mutable tags are resolved once to a digest before verification and pull so the
verified artifact is the artifact compiled and evaluated.

Optional bundles may omit both `expected_policy_revision` and manifest revision
for legacy development use. If either value is present it must use the canonical
format, and a configured expectation must match the manifest.

### Revision promotion checks

The broker is intentionally stateless and does not persist a highest-seen
revision. Release and deployment CI must compare the candidate against the tuple
from a trusted release or protected base branch. Set `BROKER_VERSION` to a
reviewed broker release or commit:

```bash
go run github.com/depthmark/github-sts/cmd/github-sts-bundle@${BROKER_VERSION} check-promotion \
  --mode=deployment \
  --current-revision="$CURRENT_REVISION" \
  --current-digest="$CURRENT_DIGEST" \
  --candidate-revision="$CANDIDATE_REVISION" \
  --candidate-digest="$CANDIDATE_DIGEST"
```

`release` mode requires a higher revision. `deployment` mode also accepts the
exact same revision/digest tuple as a no-op. Both modes reject a lower revision,
the same revision with different bytes, or one digest claiming two revisions.
Digests passed to this command are raw OCI manifest digests in canonical
`sha256:<64 lowercase hex>` form. Never derive the trusted current tuple from
candidate pull-request content. This command compares supplied tuples; CI must
first verify the candidate signature and confirm that its manifest and rendered
`expected_policy_revision` produce the supplied candidate tuple.

The first policy publication has no prior tuple to compare. Establish revision
`1` through the same protected review and signature process, then require the
comparison for every later release and deployment change.

### Optional posture signals

Optional posture is deliberately visible:

| Signal | Value |
|---|---|
| Startup log | Warning that enterprise bundle enforcement is explicitly optional; reports whether authorization is YAML-only |
| `/health.security` | `bundle_enforcement: optional`, `enterprise_policy_required: false`, and `yaml_only_authorization: true` when no bundle is configured or at least one App lacks bundle coverage |
| `/metrics` | `githubsts_bundle_enforcement_required 0` (`1` in required mode) |
| Exchange audit | `bundle_enforcement: optional` on every event; bundle digest/decisions are absent when no bundle evaluates |
