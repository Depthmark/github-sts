# syntax=docker/dockerfile:1.7
# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Builder
# Chainguard Go (Wolfi-based) — minimal, daily-rebuilt, low CVE surface.
# Pinned by multi-arch index digest so a registry-side retag cannot swap base.
# Refresh with: docker buildx imagetools inspect cgr.dev/chainguard/go:latest
# ─────────────────────────────────────────────────────────────────────────────
FROM cgr.dev/chainguard/go:latest@sha256:ebb11e4c832c36df913b7540cf651550f349ad4e3e9615a8990f57555cd7e58a AS builder

WORKDIR /build

# Pin module/build cache to fixed paths so BuildKit cache mounts are stable
# regardless of the base image's GOPATH/HOME defaults.
ENV GOMODCACHE=/cache/mod GOCACHE=/cache/build GOTOOLCHAIN=local

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/cache/mod,sharing=locked \
    go mod download && go mod verify

COPY cmd/ ./cmd/
COPY client/ ./client/
COPY internal/ ./internal/

# -trimpath: strips local filesystem paths from the binary for reproducibility
#            and to avoid leaking build environment paths.
# CGO disabled produces a fully static binary suitable for the static runtime.
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN --mount=type=cache,target=/cache/mod,sharing=locked \
    --mount=type=cache,target=/cache/build,sharing=locked \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /github-sts ./cmd/github-sts

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Runtime
# Chainguard static — distroless-equivalent: no shell, no package manager,
# nonroot uid 65532 by default. Pinned by multi-arch index digest.
# Refresh with: docker buildx imagetools inspect cgr.dev/chainguard/static:latest
# ─────────────────────────────────────────────────────────────────────────────
FROM cgr.dev/chainguard/static:latest@sha256:f51c2493951313c3ad4069080b2814ffb6ed6fe3909dabeb84a9482f42d5600b

# ── OCI image metadata ───────────────────────────────────────────────────────
# org.opencontainers.image.created is required by Artifact Hub but is NOT set
# here on purpose: it must be the real build timestamp (RFC3339). The release
# workflow injects it via docker/metadata-action, whose --label flags override
# any value baked into this file.
LABEL org.opencontainers.image.source="https://github.com/Depthmark/github-sts"
LABEL org.opencontainers.image.url="https://github.com/Depthmark/github-sts"
LABEL org.opencontainers.image.documentation="https://depthmark.github.io/github-sts/"
LABEL org.opencontainers.image.title="github-sts"
LABEL org.opencontainers.image.description="GitHub Security Token Service (STS) - OIDC to GitHub token exchange"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.vendor="Depthmark"
LABEL org.opencontainers.image.authors="Alexandre Delisle <oss@adelisle.com>"

# ── Artifact Hub metadata ────────────────────────────────────────────────────
# https://artifacthub.io/docs/topics/repositories/container-images/
# Required by Artifact Hub: io.artifacthub.package.readme-url (below, in the
# release-please block), org.opencontainers.image.created and .description.
LABEL io.artifacthub.package.category="security"
LABEL io.artifacthub.package.license="MIT"
LABEL io.artifacthub.package.logo-url="https://raw.githubusercontent.com/Depthmark/github-sts/main/docs/static/images/logo.svg"
LABEL io.artifacthub.package.keywords="github,oidc,sts,token exchange,workload identity,security,github app"
LABEL io.artifacthub.package.maintainers="[{\"name\":\"Alexandre Delisle\",\"email\":\"oss@adelisle.com\"}]"
LABEL io.artifacthub.package.prerelease="false"
LABEL io.artifacthub.package.contains-security-updates="false"

# Version-bearing labels. release-please rewrites the first semver on every
# line inside this block, so the readme URL stays pinned to the tag being
# built. readme-url must resolve to raw markdown, not rendered HTML.
# x-release-please-start-version
LABEL org.opencontainers.image.version="0.1.0"
LABEL io.artifacthub.package.readme-url="https://raw.githubusercontent.com/Depthmark/github-sts/v0.1.0/README.md"
# x-release-please-end

COPY --from=builder /github-sts /github-sts

EXPOSE 8080

# Numeric uid/gid so Kubernetes admission controllers enforcing
# `runAsNonRoot: true` can verify without resolving /etc/passwd.
USER 65532:65532

ENTRYPOINT ["/github-sts"]
