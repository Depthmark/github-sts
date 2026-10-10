---
name: publish-policy-bundle
description: Build a github-sts enterprise policy bundle, publish it to GitHub Container Registry, sign it keyless with a pinned cosign v3, and write the digest-pinned bundles block the broker admits under bundle_enforcement required. Use when a platform admin wants to publish or promote a Rego policy bundle for github-sts, asks for a bundles block or an expected_policy_revision, or has a broker that fails to start or reload with a signature_error_code, a policy revision mismatch or a bundle ref that is not pinned.
---

# Publish a github-sts policy bundle

In `required` mode the github-sts broker starts only if every bundle is an OCI reference pinned to a digest, signed in the one format it verifies, and built with the revision the configuration expects. It fails closed: a bundle it cannot admit blocks startup, and a stale one blocks exchanges. Each step below produces one value of the `bundles:` block. Copy each value from the command that produced it, never from memory or from an example.

This skill covers GitHub Container Registry and keyless signing from GitHub Actions. It does not write Rego. For another registry or for key-pair signing, point the user to the "Publishing signed bundles" page of the github-sts documentation and stop.

## Rules that hold in every step

- **Never read a secret.** Not a registry password, not a token, not a private key, not the output of `gh auth token`. The workflow below pushes with the token GitHub gives the job. If a step seems to need a secret on this machine, stop and ask the user.
- **Never loosen the configuration to get a bundle admitted.** Do not set `fail_mode: open`, `allow_mutable_ref`, `cosign.skip_verification` or `bundle_enforcement: optional`, do not replace the digest with a tag, and do not remove or edit `expected_policy_revision` to match whatever was published. If one of these looks like the only way forward, stop and ask the user.
- **Sign the digest, never the tag.** A tag can move between the push and the signature.
- **Refuse an unpinned cosign.** The signature format depends on the cosign major version, and the broker reads only the format cosign v3 writes by default. Sign only in a workflow where `sigstore/cosign-installer` is pinned to a commit SHA and `cosign-release` names an exact `v3.x.y`. If the workflow omits `cosign-release`, sets it to `latest` or to a v2 release, or calls a `cosign` that some other step put on the path, do not run it and do not sign: fix the pin first. Never sign from this machine.

## 1. Collect the inputs

Ask for whatever is missing.

| Input | Where it comes from |
| --- | --- |
| Policy repository | The `ORG/REPO` that holds the Rego. The workflow lives there, and its path becomes the signing identity. |
| Policy directory | The directory with the `.rego` and data files, such as `policy`. |
| Image path | `ghcr.io/ORG/NAME`, lowercase. For a first run, use a throwaway name. |
| Revision | A positive whole number with no leading zero, higher than the revision the broker runs today. Read today's value from `expected_policy_revision` in the broker configuration. The first publication is `1`. |
| Signing ref | The protected branch the workflow runs from, usually `refs/heads/main`. |
| Bundle role | The global baseline (`apps: []`, exactly one per broker) or an additive bundle scoped to named Apps. |

## 2. Check the revision before building

A baseline declares its revision twice: in the Rego metadata, and in the manifest that `opa build --revision` writes. The broker refuses a baseline where the two differ.

```bash
opa check --strict POLICY_DIR
opa test POLICY_DIR
opa eval --format raw -b POLICY_DIR 'data.sts.enterprise.v1.metadata.policy_revision'
```

If the last command does not print the revision from step 1, show both values to the user and ask which one is right. Changing that one string in the metadata is the only edit this skill makes to a Rego file. An additive bundle may have no such metadata: skip the third command for it.

Without `opa` on this machine, say that the local check was not run. The workflow runs the same commands before it pushes.

## 3. Write the publishing workflow

Write `.github/workflows/publish-bundle.yml` in the policy repository. Replace `ORG/NAME` and `POLICY_DIR`, and the branch in the `if:` line if the signing ref differs.

```yaml
name: Publish policy bundle

on:
  workflow_dispatch:
    inputs:
      revision:
        description: Policy revision, a positive whole number higher than the one deployed
        required: true

permissions: {}

jobs:
  publish:
    # The signing identity includes the ref. Sign from the protected branch only.
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      id-token: write
    env:
      IMAGE: ghcr.io/ORG/NAME
      POLICY_DIR: POLICY_DIR
      REVISION: ${{ inputs.revision }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - uses: open-policy-agent/setup-opa@b2b258e089860efaadaaf71bf6e3aecb4a3eeff1 # v2.4.0
        with:
          version: 1.21.1

      - uses: imjasonh/setup-crane@feee3b6bb0d4c68370f256a4502498c9227e5c6b # v0.7
        with:
          version: v0.22.1

      - uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2
        with:
          cosign-release: v3.1.3

      - name: Test and build
        run: |
          opa check --strict "$POLICY_DIR"
          opa test "$POLICY_DIR"
          # Baseline only. Delete the next two lines for an additive bundle.
          declared="$(opa eval --format raw -b "$POLICY_DIR" 'data.sts.enterprise.v1.metadata.policy_revision')"
          test "$declared" = "$REVISION" || { echo "metadata says $declared, input says $REVISION"; exit 1; }
          opa build --revision "$REVISION" -b "$POLICY_DIR" -o bundle.tar.gz
          built="$(opa inspect -f json bundle.tar.gz | jq -r .manifest.revision)"
          test "$built" = "$REVISION" || { echo "manifest says $built, input says $REVISION"; exit 1; }

      - name: Push
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: |
          echo "$GITHUB_TOKEN" | crane auth login ghcr.io --username "$GITHUB_ACTOR" --password-stdin
          # crane prints IMAGE@sha256:... for what it pushed. Keep that, and never resolve the tag again.
          pinned="$(crane append --oci-empty-base --new_layer bundle.tar.gz --new_tag "$IMAGE:r$REVISION")"
          case "$pinned" in "$IMAGE"@sha256:*) ;; *) echo "no digest from crane: $pinned"; exit 1 ;; esac
          echo "PINNED=$pinned" >> "$GITHUB_ENV"

      - name: Sign the digest
        run: cosign sign --yes "$PINNED"

      - name: Verify what the broker will verify
        run: |
          cosign verify \
            --certificate-identity "https://github.com/$GITHUB_WORKFLOW_REF" \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com \
            "$PINNED" > /dev/null

      - name: Report
        run: |
          {
            echo "ref: oci://$PINNED"
            echo "expected_policy_revision: \"$REVISION\""
            echo "signing identity: https://github.com/$GITHUB_WORKFLOW_REF"
          } >> "$GITHUB_STEP_SUMMARY"
```

Before handing it over, check the file against the rules:

1. `id-token: write` and `packages: write` are on the job, and the top-level `permissions` is empty.
2. Every action is pinned to a 40-character SHA, and `cosign-release` is an exact `v3.x.y`.
3. `cosign sign` receives `$PINNED`, which contains `@sha256:`. No command signs `$IMAGE:` followed by a tag.
4. No step takes a secret other than the token GitHub gives the job.

To move a pin, resolve the SHA with `git ls-remote --tags https://github.com/OWNER/ACTION` and keep the tag in the trailing comment. Keep cosign on v3.

## 4. Run it and read the result

The user merges the workflow to the signing ref and runs it with the revision, from the Actions tab or with `gh workflow run publish-bundle.yml -f revision=N`. Do not run it from a pull request branch: the signature would carry that branch in its identity, and the broker would refuse it.

Read the three lines from the run summary, or ask the user to paste them. Check them before going on:

- The ref ends with `@sha256:` and 64 lowercase hexadecimal characters.
- The revision is the one from step 1.
- The signing identity ends with `@` and the signing ref.

## 5. Write the bundles block

```yaml
bundle_enforcement: required

bundles:
  - name: enterprise-baseline
    apps: []
    ref: oci://ghcr.io/ORG/NAME@sha256:DIGEST
    expected_policy_revision: "N"
    fail_mode: closed
    cosign:
      certificate_identity_regexp: '^https://github\.com/ORG/REPO/\.github/workflows/publish-bundle\.yml@refs/heads/main$'
      certificate_oidc_issuer: https://token.actions.githubusercontent.com
```

- `ref` is the first line of the run summary, character for character.
- `expected_policy_revision` is a quoted string.
- `certificate_identity_regexp` is the signing identity from the run summary with every literal dot escaped, anchored with `^` and `$`, in single quotes. Do not widen it with `.*` to cover other branches or workflows: it decides who may publish policy for the whole broker.
- For an additive bundle, set `name` to a new name and `apps` to the App names it covers. `fail_mode: closed` is mandatory on the baseline.

If the package is private, the broker needs a credential that can read it. Add the block below with the name of an environment variable, and tell the user to put a token with `read:packages` in that variable on the broker. Never ask for the token and never write its value.

```yaml
    registry:
      auth:
        mode: basic
        username: USERNAME
        password_env: GHCR_READ_TOKEN
```

When the block replaces a deployed one, the new revision must be higher and the digest different. The same revision with a different digest, or a lower revision, is a rollback: stop and ask.

## 6. Confirm the broker admits it

After the user deploys the configuration, ask them to run this against the broker and paste the output. If `/health` needs a token, they add the header themselves.

```bash
curl -s https://STS_HOST/health | jq '{security: .security.bundle_enforcement, bundles: [.bundles[] | {name, mandatory, enabled, digest, policy_revision}]}'
```

The bundle is admitted when `security` is `required`, exactly one bundle has `mandatory: true`, its `digest` is the one in `ref`, and its `policy_revision` equals `expected_policy_revision`. Say so only after reading that output.

## 7. When the broker refuses the bundle

A signature failure writes one log line with `signature_error_code` and `signature_operation`, followed by the startup or reload error that carries the cause:

```json
{"level":"ERROR","msg":"bundle init: signature verification failed","bundle":"enterprise-baseline","signature_error_code":"signature_not_found","signature_operation":"classify_referrer"}
```

Name the phase and the fix from this table. The fix is always on the publishing side or on registry access, never a relaxed setting.

| `signature_error_code` | `signature_operation` | Phase that failed | Fix |
| --- | --- | --- | --- |
| `signature_not_found` | `classify_referrer` | The registry listed what is attached to the digest, and no Sigstore bundle signature is among it. | The digest was never signed, or was signed with cosign v2, which writes only a legacy `sha256-DIGEST.sig` tag that the broker does not read. Pin `cosign-release` to `v3.1.3` in the workflow and run it again. Also compare the digest in `ref` with the one the workflow signed. |
| `discovery_failed` | `referrer_discovery` or `fetch_referrer_manifest` | The broker could not list or read what is attached to the digest: access denied, rate limit, timeout or server error. | Fix the broker's access to the package. With a pinned ref this is the broker's first call to the registry, so a private package with no `registry` block, or a token without `read:packages`, lands here. Do not re-sign. |
| `unsupported_signature_format` | `classify_referrer` | A signature is attached, in the transitional OCI 1.1 format or in a Sigstore bundle version this broker cannot read. | Remove `COSIGN_EXPERIMENTAL` and `--registry-referrers-mode` from the workflow and sign again with cosign v3 defaults. |
| `malformed_signature` | `fetch_referrer_manifest`, `classify_referrer` or `resolve` | A signature is attached but cannot be read, or it names another digest. With `resolve`, the reference handed to the verifier was not a digest. | Publish and sign again with the workflow, then pin the new digest. With `resolve`, restore the `@sha256:` pin in `ref`. |
| `predicate_mismatch` | `verify_standardized` | The signature and the identity verified, but the signed statement is an attestation such as an SBOM or provenance, not a cosign signature. | Sign with `cosign sign`, as in the workflow. `cosign attest` does not authorize a bundle. |
| `cryptographic_verification_failed` | `verify_standardized` | The signature, the certificate identity, the issuer or the transparency log entry did not match. | Read the cause in the error that follows. Most often `certificate_identity_regexp` does not match the signing identity in the run summary: another workflow file, another ref, or an unescaped character. Correct the regular expression to that exact identity, or sign again from the right ref. |
| `trust_root_unavailable` | `load_trusted_root` or `load_public_key` | Verification did not start: the broker could not load the Sigstore trusted root, or the public key file in key mode. | Allow outbound HTTPS from the broker to the Sigstore TUF mirror, `tuf-repo-cdn.sigstore.dev`. With `load_public_key`, the configuration uses a key, which this skill does not cover. |

Three refusals carry no signature code:

| Error text | Fix |
| --- | --- |
| `ref must be an OCI reference pinned exactly to @sha256:` | The `ref` holds a tag or a malformed digest. Copy the ref from the run summary. |
| `expected policy revision "A" does not match bundle manifest revision "B"` | The configuration and the digest come from two different runs. Take both lines from the same run summary. Do not edit one to match the other. |
| `mandatory metadata policy_revision "A" does not match manifest revision "B"` | The Rego metadata was not updated for this revision. Go back to step 2 and publish a new revision. |

Any other admission failure of a baseline, such as a missing decision document or a failed probe, is in the Rego itself. Report the error text to the user and stop.

## 8. Hand over

Tell the user, in this order:

1. The pinned ref and the full `bundles:` block.
2. The signing identity, and that anyone who can run that workflow on that ref can publish policy the broker will accept.
3. What was not checked: the local `opa` commands, the `/health` output, or the broker's access to a private package.
4. That every later policy change is a new revision, a new digest and a new rollout of this block.
