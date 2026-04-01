# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Builder
# Compile the Go binary with CGO disabled for static linking
# ─────────────────────────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS builder

WORKDIR /build

# Copy dependency files first (better layer caching)
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    go mod download && go mod verify

# Copy source
COPY cmd/ ./cmd/
COPY client/ ./client/
COPY internal/ ./internal/

# Build static binary — cache mounts persist the module cache and Go build cache
# across builds so only changed packages are recompiled.
# sharing=locked: prevents cache corruption from parallel multi-platform builds.
# -trimpath: strips local filesystem paths from the binary for reproducibility
#            and to avoid leaking build environment paths.
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /github-sts ./cmd/github-sts

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Runtime
# Distroless static image — no shell, no package manager, minimal attack surface
# ─────────────────────────────────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot

LABEL maintainer="Alexandre Delisle <oss@adelisle.com>"
LABEL description="GitHub Security Token Service (STS) - OIDC to GitHub token exchange"
# x-release-please-start-version
LABEL version="0.0.2"
# x-release-please-end

# Copy the static binary from builder
COPY --from=builder /github-sts /github-sts

# Expose port
EXPOSE 8080

# Distroless nonroot image runs as uid 65534 by default
USER nonroot:nonroot

# Entrypoint
ENTRYPOINT ["/github-sts"]
