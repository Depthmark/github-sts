# github-sts

Exchange OIDC tokens for short-lived, scoped GitHub installation tokens. No PATs. No long-lived secrets.

Workloads with OIDC tokens (GitHub Actions, Azure, GCP, any IdP) present their identity and receive a **least-privilege GitHub token** scoped to exactly the repositories and permissions they need. Supports **multiple GitHub Apps** with YAML-based configuration, making it ideal for Kubernetes ConfigMaps.

Inspired by [octo-sts/app](https://github.com/octo-sts/app), which pioneered OIDC federation for GitHub token exchange.

## Highlights

| | Feature | Description |
|---|---|---|
| **Zero-trust** | OIDC Federation | No stored credentials — identity verified via OIDC JWT validation |
| **Least-privilege** | Policy-based Scoping | YAML trust policies define exact permissions per workload identity |
| **Enterprise policy** | Mandatory Bundle Contract | Required mode enforces a signed, digest-pinned global baseline plus additive app controls |
| **Multi-app** | Multiple GitHub Apps | Route different workloads through different GitHub Apps |
| **Immutable target** | Repository ID Scoping | Resolve canonical targets and mint using exact GitHub repository IDs |
| **Observable** | Prometheus Metrics | Built-in metrics and structured audit logging |
| **Replay-safe** | JTI Cache | Memory or Redis-backed JTI tracking prevents token replay attacks |
| **Portable** | Distroless Container | Single static binary in a minimal container — runs anywhere |

## Where to next

- **New here?** Start with [Getting Started](getting-started.md) to run github-sts locally and exchange your first token.
- **Operating it?** [Configuration](configuration.md) covers YAML and environment variables; [Deployment](deployment.md) covers Docker and Helm.
- **Integrating?** [API Reference](api-reference.md) documents `/sts/exchange`, error codes, and the Go client library.
- **Curious how it works?** [Architecture](architecture.md) explains the OIDC → policy → token flow and project layout.
- **Issuer setup?** [OIDC Issuers](oidc-issuers.md) has per-provider snippets (GitHub Actions, Azure, GCP, …).

## License

[MIT License](https://github.com/Depthmark/github-sts/blob/main/LICENSE) — Copyright (c) 2026 Alexandre Delisle
