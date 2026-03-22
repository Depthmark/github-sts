# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Builder
# Install build tools and create wheels from pyproject.toml
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.14-slim AS builder

# Harden pip behaviour
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Install build tooling
RUN pip install --no-cache-dir build

# Copy only dependency files first (better layer caching)
COPY pyproject.toml README.md ./

# Copy source
COPY src/ ./src/

# Build the wheel from pyproject.toml
RUN python -m build --wheel --outdir /dist

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Runtime
# Minimal image — just install the built wheel
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.14-alpine AS runtime

LABEL maintainer="Alexandre Delisle <oss@adelisle.com>"
LABEL description="GitHub Security Token Service (STS) - OIDC to GitHub token exchange"
# x-release-please-start-version
LABEL version="0.1.1"
# x-release-please-end

# Harden Python runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install runtime-only OS deps and remove apk cache
RUN apk add --no-cache libgcc libstdc++

# Create a non-root user/group (Alpine adduser/addgroup)
RUN addgroup -S appuser && \
    adduser -S -G appuser -h /home/appuser -s /sbin/nologin appuser

# Copy only the built wheel from the builder stage
COPY --from=builder /dist/*.whl /tmp/

# Install the wheel, then remove pip & setuptools to shrink attack surface
RUN pip install --no-cache-dir --no-compile /tmp/*.whl && \
    rm -rf /tmp/*.whl && \
    pip uninstall -y pip setuptools 2>/dev/null; true

# Switch to non-root user
USER appuser
WORKDIR /home/appuser

# Expose port
EXPOSE 8080

# Health check using wget (built into Alpine, no Python import overhead)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO /dev/null http://localhost:8080/health || exit 1

# Set the default command to run the FastAPI app with uvicorn
CMD ["python", "-m", "uvicorn", "github_sts.main:app", "--host", "0.0.0.0", "--port", "8080"]


