# Load Testing

## Prerequisites

- Go (version from `go.mod`)
- No external services required — all backends are mocked

## Run All Load Tests

```bash
go test -tags e2e -v -count=1 ./e2e/
```

## Run Individual Tests

```bash
# Sustained throughput (50 workers, 10s)
go test -tags e2e -v -count=1 -run TestLoad_SustainedThroughput ./e2e/

# Burst handling (200 concurrent requests)
go test -tags e2e -v -count=1 -run TestLoad_BurstHandling ./e2e/

# Multi-app isolation (3 apps, 100 req each)
go test -tags e2e -v -count=1 -run TestLoad_MultiAppIsolation ./e2e/

# JTI replay detection (1 token, 100 concurrent replays)
go test -tags e2e -v -count=1 -run TestLoad_JTIReplayUnderLoad ./e2e/

# Cache efficiency (warmup + steady-state API call tracking)
go test -tags e2e -v -count=1 -run TestLoad_CacheEfficiency ./e2e/

# Graceful degradation (upstream 503 handling)
go test -tags e2e -v -count=1 -run TestLoad_GracefulDegradation ./e2e/
```
