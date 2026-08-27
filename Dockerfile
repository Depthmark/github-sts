# syntax=docker/dockerfile:1.7
# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Builder
# Chainguard Go (Wolfi-based) — minimal, daily-rebuilt, low CVE surface.
# Pinned by multi-arch index digest so a registry-side retag cannot swap base.
# Refresh with: docker buildx imagetools inspect cgr.dev/chainguard/go:latest
# ─────────────────────────────────────────────────────────────────────────────
FROM cgr.dev/chainguard/go:latest@sha256:d54b1367a7096e816d3629e74f6bcb0dc3f789936e677041fafbee9ab37350fe AS builder

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
FROM cgr.dev/chainguard/static:latest@sha256:f68e3a8244c7d0f4cd56635aaff8e6a533cf6cc3850d8fb339567a5782d6a0b0

LABEL org.opencontainers.image.source="https://github.com/Depthmark/github-sts"
LABEL org.opencontainers.image.description="GitHub Security Token Service (STS) - OIDC to GitHub token exchange"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.authors="Alexandre Delisle <oss@adelisle.com>"
# x-release-please-start-version
LABEL org.opencontainers.image.version="0.0.4"
# x-release-please-end

COPY --from=builder /github-sts /github-sts

EXPOSE 8080

# Numeric uid/gid so Kubernetes admission controllers enforcing
# `runAsNonRoot: true` can verify without resolving /etc/passwd.
USER 65532:65532

ENTRYPOINT ["/github-sts"]
