---
title: Publishing signed bundles
description: Minimum cosign and registry versions for a verifiable policy bundle, plus publishing examples for GHCR, Harbor, Nexus, and Artifactory.
weight: 7
translationKey: publishing-bundles
---

`github-sts` verifies exactly one signature format: a standardized Sigstore
bundle stored as an OCI 1.1 referrer. This page covers the versions that produce
it and how to publish one to four common registries.

See [Compatibility]({{< relref "/integrations/compatibility" >}}) for what
happens when a bundle is signed some other way.

## Minimum versions

### Cosign

| Version | Result |
|---|---|
| v3.0.0 and later | Produces the supported format by default. Recommended |
| v2.6.5 | Produces it only with `--new-bundle-format=true`. Tested and accepted |
| v2.x defaults | Produces the legacy `sha256-<digest>.sig` tag, which is not verified |

Cosign v3 flipped `--new-bundle-format` to default true and deprecated the flag.
The practical consequence is that the format written depends on the cosign major
version, so **pin cosign in the publishing pipeline**. An unpinned `cosign` on
`$PATH`, or an installer action's default, silently decides whether the bundle
you publish can be verified at all.

### Registry

The registry must accept an OCI 1.1 image manifest carrying a `subject` field.
The OCI Referrers API is preferred but not required: `github-sts` falls back to
the referrers tag scheme when a registry does not implement the API.

| Registry | Minimum version | Notes |
|---|---|---|
| GitHub Container Registry | Not applicable, hosted | Referrers API supported for read and write |
| Harbor | 2.8 began OCI 1.1 distribution support, extended through 2.9 | Verified working on 2.15. Harbor's UI may label a cosign v3 signature as an unknown accessory type; that is a display issue and does not affect verification |
| JFrog Artifactory | 7.90.1 | Referrers API added in this release |
| Sonatype Nexus Repository | 3.94.0 | OCI repositories, including Referrers API support, are new in this release |

Registry version numbers move, and vendors backport. Treat the table as a
starting point and confirm with the probe below rather than trusting it.

## Check your registry before relying on it

Publish and sign one throwaway artifact, then read back what the registry
actually stored. This takes a minute and answers the question the version table
only estimates.

```bash
REF="<registry>/<path>/probe:$(date +%s)"
echo probe > probe.txt
crane append --oci-empty-base --new_layer probe.txt --new_tag "$REF"
DIGEST="$(crane digest "$REF")"
cosign sign --key cosign.key --yes "${REF%%:*}@${DIGEST}"

# Ask for referrers. A JSON index means the Referrers API is live.
curl -s -H "Accept: application/vnd.oci.image.index.v1+json" \
  "https://<registry>/v2/<path>/probe/referrers/${DIGEST}"

# A 404 above is fine. It means the tag fallback is in use, so look there:
curl -s "https://<registry>/v2/<path>/probe/manifests/${DIGEST/:/-}"
```

Either response must list a manifest whose layer media type is
`application/vnd.dev.sigstore.bundle.v0.3+json`. If neither does, the registry
did not store the signature in a form `github-sts` can find.

The descriptor in the tag-fallback index may report `artifactType` as
`application/vnd.oci.empty.v1+json` rather than the bundle type. That is a known
cosign limitation on registries without the Referrers API. `github-sts` fetches
each referrer manifest rather than trusting the listing, so the signature is
still found.

## Build the bundle

Identical for every registry. Build with an explicit revision so the broker can
match it against `expected_policy_revision`:

```bash
opa build --revision 42 -b policy -o bundle.tar.gz

crane append \
  --oci-empty-base \
  --new_layer bundle.tar.gz \
  --new_tag "<registry>/<path>/policy:v1.0.0"

# Sign the digest, never the tag: a tag can move between signing and pulling.
DIGEST="$(crane digest "<registry>/<path>/policy:v1.0.0")"
```

## Publish and sign

Only authentication and the reference shape differ between registries. The
signing command is the same everywhere.

### GitHub Container Registry

```bash
echo "$GITHUB_TOKEN" | crane auth login ghcr.io --username "$GITHUB_ACTOR" --password-stdin
REPO="ghcr.io/<org>/<repository>"
```

In a workflow, sign keyless and skip key management entirely. The job needs
`id-token: write` and `packages: write`:

```yaml
- uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2
  with:
    cosign-release: v3.1.3   # pin it; the installer default is not a contract
- run: cosign sign --yes "${REPO}@${DIGEST}"
```

Configure the broker with the workflow identity that signed it:

```yaml
cosign:
  certificate_identity_regexp: '^https://github\.com/<org>/<repo>/\.github/workflows/release\.yml@refs/tags/v.*$'
  certificate_oidc_issuer: https://token.actions.githubusercontent.com
```

### Harbor

Use a robot account scoped to the project rather than a user login.

```bash
echo "$HARBOR_ROBOT_SECRET" | crane auth login harbor.example.com \
  --username 'robot$policy-publisher' --password-stdin
REPO="harbor.example.com/<project>/policy"

cosign sign --key cosign.key --yes "${REPO}@${DIGEST}"
```

Harbor is usually behind a private CA. `github-sts` has no CA configuration: it
uses the system trust store, so the CA must be installed in the broker's
container. Without it the pull fails with an x509 error before verification
runs, and the failure is counted as a pull failure rather than a signature one.

### Sonatype Nexus Repository

Publish to an OCI repository, not a legacy Docker repository. The Referrers API
arrived with the OCI repository format in 3.94.0.

```bash
echo "$NEXUS_PASSWORD" | crane auth login nexus.example.com \
  --username "$NEXUS_USER" --password-stdin
REPO="nexus.example.com/<oci-repository>/policy"

cosign sign --key cosign.key --yes "${REPO}@${DIGEST}"
```

If the repository is served on a non-default port, include it in the reference:
`nexus.example.com:8443/<oci-repository>/policy`.

### JFrog Artifactory

```bash
echo "$ARTIFACTORY_TOKEN" | crane auth login artifactory.example.com \
  --username "$ARTIFACTORY_USER" --password-stdin
REPO="artifactory.example.com/<docker-repository>/policy"

cosign sign --key cosign.key --yes "${REPO}@${DIGEST}"
```

Artifactory needs 7.90.1 or later for the Referrers API. On an older instance
the signature is written through the tag fallback, which `github-sts` still
reads.

## Verify before pointing the broker at it

Check the signature with cosign first, so a verification failure in the broker
is never ambiguous between a bad signature and a bad configuration:

```bash
cosign verify --key cosign.pub "${REPO}@${DIGEST}"
```

Then configure the broker against the same immutable digest:

```yaml
bundles:
  - name: enterprise-baseline
    apps: []
    ref: oci://<registry>/<path>/policy@sha256:<digest>
    expected_policy_revision: "42"
    fail_mode: closed
    cosign:
      public_key_ref: /etc/github-sts/cosign.pub
    registry_auth:
      mode: basic
      username: policy-reader
      password_env: REGISTRY_PASSWORD
```

The credentials the broker uses must be able to list referrers, not only pull
the manifest. A pull-only account produces `discovery_failed` rather than a
missing-signature error. See
[Troubleshooting]({{< relref "/operations/troubleshooting" >}}) for the full
error-code table.
