"""
See a configuration example at `config/github-sts.example.yaml`
"""

import logging
import os
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, model_validator

logger = logging.getLogger(__name__)

# ── Sub-models ────────────────────────────────────────────────────────────────


class LoggingConfig(BaseModel):
    """Multi-channel logging configuration."""

    level: str = "INFO"  # app channel level
    access_level: str = "INFO"  # access channel level
    suppress_health_logs: bool = True  # filter probes at INFO
    audit_file_enabled: bool = True  # write audit to rotating file
    audit_file_path: str = "/var/log/github-sts/audit.json"
    audit_file_max_bytes: int = 10_485_760  # 10 MB
    audit_file_backup_count: int = 5


class ServerConfig(BaseModel):
    """Server settings."""

    host: str = "0.0.0.0"
    port: int = 8080
    log_level: str = "INFO"  # backward compat — seeds logging.level
    logging: LoggingConfig = LoggingConfig()


class PolicyConfig(BaseModel):
    """Policy resolution settings."""

    backend: str = "github"
    base_path: str = ".github/sts"  # Base path in repo for policy files
    cache_ttl_seconds: int = 60  # 0 = disable cache


class AppConfig(BaseModel):
    """
    A single GitHub App configuration.

    The app name (dict key) is used in the policy path:
      {policy.base_path}/{app_name}/{identity}.sts.yaml
    """

    app_id: int
    private_key: str | None = None  # PEM contents directly
    private_key_path: str | None = None  # Path to PEM file

    @model_validator(mode="after")
    def resolve_private_key(self) -> "AppConfig":  # noqa: UP037
        """Load private key from file if private_key_path is given."""
        if self.private_key and not self.private_key.startswith("-----BEGIN"):
            # Treat as file path for backward compat
            try:
                self.private_key = Path(self.private_key).read_text()
            except FileNotFoundError:
                pass

        if not self.private_key and self.private_key_path:
            try:
                self.private_key = Path(self.private_key_path).read_text()
            except FileNotFoundError as exc:
                raise ValueError(
                    f"Private key file not found: {self.private_key_path}"
                ) from exc

        if not self.private_key:
            raise ValueError(
                "Either 'private_key' or 'private_key_path' must be provided"
            )
        return self


class OIDCConfig(BaseModel):
    """OIDC validation settings."""

    allowed_issuers: list[str] = []  # Empty = allow any issuer

    @model_validator(mode="before")
    @classmethod
    def _coerce_none_fields(cls, data: dict) -> dict:
        """YAML renders an empty key as None; coerce to default."""
        if isinstance(data, dict) and data.get("allowed_issuers") is None:
            data["allowed_issuers"] = []
        return data


class JTIConfig(BaseModel):
    """JTI replay prevention settings."""

    backend: str = "memory"  # "memory" or "redis"
    redis_url: str | None = None  # Required if backend=redis
    ttl_seconds: int = 3600  # Match token lifetime


class AuditConfig(BaseModel):
    """Audit logging settings."""

    file_path: str = "./audit.log"
    rotation_policy: str = "daily"  # "daily" or "size"
    rotation_size_bytes: int = 100 * 1024 * 1024  # 100MB


class MetricsConfig(BaseModel):
    """Prometheus metrics settings."""

    enabled: bool = True
    prefix: str = "pygithubsts"
    rate_limit_poll_enabled: bool = True
    rate_limit_poll_interval_seconds: int = 60
    reachability_probe_enabled: bool = True
    reachability_probe_interval_seconds: int = 30


# ── Root configuration ────────────────────────────────────────────────────────


class Settings(BaseModel):
    """
    Root configuration model for github-sts.

    Supports YAML file loading and env var overrides.
    """

    server: ServerConfig = ServerConfig()
    policy: PolicyConfig = PolicyConfig()
    apps: dict[str, AppConfig] = {}
    oidc: OIDCConfig = OIDCConfig()
    jti: JTIConfig = JTIConfig()
    audit: AuditConfig = AuditConfig()
    metrics: MetricsConfig = MetricsConfig()

    # ── Convenience accessors ─────────────────────────────────────────────

    @property
    def allowed_issuers_list(self) -> list[str] | None:
        """Return allowed issuers or None if unrestricted."""
        return self.oidc.allowed_issuers if self.oidc.allowed_issuers else None

    def get_app(self, app_name: str) -> AppConfig:
        """
        Get a GitHub App config by name.

        Raises KeyError if not found.
        """
        if app_name not in self.apps:
            available = ", ".join(self.apps.keys()) or "(none)"
            raise KeyError(
                f"GitHub App {app_name!r} not configured. Available apps: {available}"
            )
        return self.apps[app_name]

    @property
    def default_app_name(self) -> str | None:
        """Return the default app name (first configured app, or None)."""
        if len(self.apps) == 1:
            return next(iter(self.apps))
        return None

    @property
    def app_names(self) -> list[str]:
        """Return list of configured app names."""
        return list(self.apps.keys())


# ── Loading logic ─────────────────────────────────────────────────────────────

ENV_PREFIX = "PYGITHUBSTS_"


def _load_yaml_config(config_path: str) -> dict:
    """Load configuration from a YAML file."""
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(path) as f:
        data = yaml.safe_load(f)

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(
            f"Config file must be a YAML mapping, got {type(data).__name__}"
        )

    return data


def _apply_env_overrides(config: dict) -> dict:
    """
    Apply environment variable overrides to the config dict.

    Supported env vars (with PYGITHUBSTS_ prefix):
      PYGITHUBSTS_SERVER_HOST, PYGITHUBSTS_SERVER_PORT, PYGITHUBSTS_SERVER_LOG_LEVEL
      PYGITHUBSTS_POLICY_BACKEND, PYGITHUBSTS_POLICY_BASE_PATH,
      PYGITHUBSTS_POLICY_CACHE_TTL_SECONDS
      PYGITHUBSTS_JTI_BACKEND, PYGITHUBSTS_JTI_REDIS_URL, PYGITHUBSTS_JTI_TTL_SECONDS
      PYGITHUBSTS_AUDIT_FILE_PATH, PYGITHUBSTS_AUDIT_ROTATION_POLICY
      PYGITHUBSTS_METRICS_ENABLED, PYGITHUBSTS_METRICS_PREFIX
      PYGITHUBSTS_OIDC_ALLOWED_ISSUERS (comma-separated)

    For apps (single-app shortcut):
      PYGITHUBSTS_GITHUB_APP_ID, PYGITHUBSTS_GITHUB_APP_PRIVATE_KEY
      PYGITHUBSTS_GITHUB_APP_NAME (default: "default")
    """
    # ── Server overrides ──────────────────────────────────────────────────
    server = config.setdefault("server", {})
    if v := os.environ.get(f"{ENV_PREFIX}SERVER_HOST"):
        server["host"] = v
    if v := os.environ.get(f"{ENV_PREFIX}SERVER_PORT"):
        server["port"] = int(v)
    if v := os.environ.get(f"{ENV_PREFIX}SERVER_LOG_LEVEL"):
        server["log_level"] = v

    # ── Logging overrides ─────────────────────────────────────────────
    logging_cfg = server.setdefault("logging", {})
    if v := os.environ.get(f"{ENV_PREFIX}LOGGING_LEVEL"):
        logging_cfg["level"] = v
    if v := os.environ.get(f"{ENV_PREFIX}LOGGING_ACCESS_LEVEL"):
        logging_cfg["access_level"] = v
    if v := os.environ.get(f"{ENV_PREFIX}LOGGING_SUPPRESS_HEALTH_LOGS"):
        logging_cfg["suppress_health_logs"] = v.lower() in ("true", "1", "yes")
    if v := os.environ.get(f"{ENV_PREFIX}LOGGING_AUDIT_FILE_ENABLED"):
        logging_cfg["audit_file_enabled"] = v.lower() in ("true", "1", "yes")
    if v := os.environ.get(f"{ENV_PREFIX}LOGGING_AUDIT_FILE_PATH"):
        logging_cfg["audit_file_path"] = v
    if v := os.environ.get(f"{ENV_PREFIX}LOGGING_AUDIT_FILE_MAX_BYTES"):
        logging_cfg["audit_file_max_bytes"] = int(v)
    if v := os.environ.get(f"{ENV_PREFIX}LOGGING_AUDIT_FILE_BACKUP_COUNT"):
        logging_cfg["audit_file_backup_count"] = int(v)

    # ── Policy overrides ──────────────────────────────────────────────────
    policy = config.setdefault("policy", {})
    if v := os.environ.get(f"{ENV_PREFIX}POLICY_BACKEND"):
        policy["backend"] = v
    if v := os.environ.get(f"{ENV_PREFIX}POLICY_BASE_PATH"):
        policy["base_path"] = v
    if v := os.environ.get(f"{ENV_PREFIX}POLICY_CACHE_TTL_SECONDS"):
        policy["cache_ttl_seconds"] = int(v)

    # ── JTI overrides ─────────────────────────────────────────────────────
    jti = config.setdefault("jti", {})
    if v := os.environ.get(f"{ENV_PREFIX}JTI_BACKEND"):
        jti["backend"] = v
    if v := os.environ.get(f"{ENV_PREFIX}JTI_REDIS_URL"):
        jti["redis_url"] = v
    if v := os.environ.get(f"{ENV_PREFIX}JTI_TTL_SECONDS"):
        jti["ttl_seconds"] = int(v)

    # ── Audit overrides ───────────────────────────────────────────────────
    audit = config.setdefault("audit", {})
    if v := os.environ.get(f"{ENV_PREFIX}AUDIT_FILE_PATH"):
        audit["file_path"] = v
    if v := os.environ.get(f"{ENV_PREFIX}AUDIT_ROTATION_POLICY"):
        audit["rotation_policy"] = v
    if v := os.environ.get(f"{ENV_PREFIX}AUDIT_ROTATION_SIZE_BYTES"):
        audit["rotation_size_bytes"] = int(v)

    # ── Metrics overrides ─────────────────────────────────────────────────
    metrics = config.setdefault("metrics", {})
    if v := os.environ.get(f"{ENV_PREFIX}METRICS_ENABLED"):
        metrics["enabled"] = v.lower() in ("true", "1", "yes")
    if v := os.environ.get(f"{ENV_PREFIX}METRICS_PREFIX"):
        metrics["prefix"] = v
    if v := os.environ.get(f"{ENV_PREFIX}METRICS_RATE_LIMIT_POLL_ENABLED"):
        metrics["rate_limit_poll_enabled"] = v.lower() in ("true", "1", "yes")
    if v := os.environ.get(f"{ENV_PREFIX}METRICS_RATE_LIMIT_POLL_INTERVAL_SECONDS"):
        metrics["rate_limit_poll_interval_seconds"] = int(v)
    if v := os.environ.get(f"{ENV_PREFIX}METRICS_REACHABILITY_PROBE_ENABLED"):
        metrics["reachability_probe_enabled"] = v.lower() in ("true", "1", "yes")
    if v := os.environ.get(f"{ENV_PREFIX}METRICS_REACHABILITY_PROBE_INTERVAL_SECONDS"):
        metrics["reachability_probe_interval_seconds"] = int(v)

    # ── OIDC overrides ────────────────────────────────────────────────────
    oidc = config.setdefault("oidc", {})
    if v := os.environ.get(f"{ENV_PREFIX}OIDC_ALLOWED_ISSUERS"):
        oidc["allowed_issuers"] = [i.strip() for i in v.split(",") if i.strip()]

    # ── App overrides (single-app env var shortcut) ───────────────────────
    app_id = os.environ.get(f"{ENV_PREFIX}GITHUB_APP_ID")
    app_key = os.environ.get(f"{ENV_PREFIX}GITHUB_APP_PRIVATE_KEY")
    app_key_path = os.environ.get(f"{ENV_PREFIX}GITHUB_APP_PRIVATE_KEY_PATH")
    if app_id:
        app_name = os.environ.get(f"{ENV_PREFIX}GITHUB_APP_NAME", "default")
        apps = config.setdefault("apps", {})
        app_cfg = apps.setdefault(app_name, {})
        app_cfg["app_id"] = int(app_id)
        if app_key:
            app_cfg["private_key"] = app_key
        if app_key_path:
            app_cfg["private_key_path"] = app_key_path

    return config


def load_settings() -> Settings:
    """
    Load settings from YAML file and/or environment variables.

    Priority (highest to lowest):
      1. Environment variables (PYGITHUBSTS_* prefix)
      2. YAML config file (path from PYGITHUBSTS_CONFIG_PATH)
      3. Defaults
    """
    config: dict = {}

    # Load from YAML file if specified
    config_path = os.environ.get(f"{ENV_PREFIX}CONFIG_PATH")
    if config_path:
        logger.info("Loading config from %s", config_path)
        config = _load_yaml_config(config_path)

    # Apply env var overrides
    config = _apply_env_overrides(config)

    return Settings(**config)


@lru_cache
def get_settings() -> Settings:
    """Cached singleton for application settings."""
    return load_settings()
