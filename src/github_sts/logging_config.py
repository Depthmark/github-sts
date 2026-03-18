"""
Structured multi-channel logging configuration.

Three logical channels, distinguished by a ``log_channel`` JSON field
that Promtail / Loki (or any aggregator) can label-route:

  ============  =========================  ================================
  Channel       Logger name                Purpose
  ============  =========================  ================================
  **access**    ``github_sts.access``       HTTP request / response lines
  **app**       ``github_sts`` (+ children) Business logic, OIDC, policy …
  **audit**     ``github_sts.audit``        Security audit events
  ============  =========================  ================================

All channels write JSON-Lines to **stdout** (for ``kubectl logs``).
The audit channel additionally writes to a rotating file so that
Promtail can tail it independently.
"""

import json
import logging
import logging.handlers
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar

from .request_context import get_trace_id

# Standard LogRecord attributes to exclude when extracting extras
_STANDARD_ATTRS: frozenset[str] = frozenset(
    logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys()
    | {
        "message",
        "asctime",
        "relativeCreated",
        "msecs",
        "stack_info",
        "taskName",
    }
)


class JSONFormatter(logging.Formatter):
    """JSON-Lines formatter with ``trace_id`` and ``log_channel`` injection."""

    CHANNEL_MAP: ClassVar[dict[str, str]] = {
        "github_sts.access": "access",
        "github_sts.audit": "audit",
    }

    def format(self, record: logging.LogRecord) -> str:
        log_channel = self.CHANNEL_MAP.get(record.name, "app")

        log_data: dict = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "log_channel": log_channel,
            "trace_id": get_trace_id(),
            "logger": record.name,
            "message": record.getMessage(),
        }

        if record.exc_info and record.exc_info[1]:
            log_data["exception"] = self.formatException(record.exc_info)

        # Merge extra fields passed via ``extra={}`` into the top-level JSON
        for key, value in record.__dict__.items():
            if key not in _STANDARD_ATTRS and not key.startswith("_"):
                log_data[key] = value

        return json.dumps(log_data, default=str)


class HealthLogFilter(logging.Filter):
    """Suppress health / ready / metrics access logs unless level is DEBUG."""

    SUPPRESSED_PATHS: frozenset[str] = frozenset(
        {"/healthz", "/readyz", "/health", "/ready", "/metrics"}
    )

    def filter(self, record: logging.LogRecord) -> bool:
        path = getattr(record, "path", None)
        if path in self.SUPPRESSED_PATHS and record.levelno == logging.INFO:
            return False
        return True


def setup_logging(
    level: str = "INFO",
    access_level: str = "INFO",
    suppress_health_logs: bool = True,
    audit_file_enabled: bool = True,
    audit_file_path: str = "/var/log/github-sts/audit.json",
    audit_file_max_bytes: int = 10_485_760,
    audit_file_backup_count: int = 5,
) -> None:
    """Configure the three logging channels.

    Call **once** at startup, before any request is served.
    """
    formatter = JSONFormatter()
    resolved_level = getattr(logging, level.upper(), logging.INFO)
    resolved_access_level = getattr(logging, access_level.upper(), logging.INFO)

    # ── Root logger — catch-all for third-party libs ─────────────────────
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.handlers.clear()

    root_handler = logging.StreamHandler(sys.stdout)
    root_handler.setFormatter(formatter)
    root_handler.setLevel(logging.WARNING)
    root.addHandler(root_handler)

    # ── App logger (github_sts.*) — business logic channel ───────────────
    app_logger = logging.getLogger("github_sts")
    app_logger.setLevel(resolved_level)
    app_logger.propagate = False
    app_logger.handlers.clear()

    app_handler = logging.StreamHandler(sys.stdout)
    app_handler.setFormatter(formatter)
    app_handler.setLevel(resolved_level)
    app_logger.addHandler(app_handler)

    # ── Access logger — route-level request / response ───────────────────
    access_logger = logging.getLogger("github_sts.access")
    access_logger.setLevel(logging.DEBUG)  # let handler/filter decide
    access_logger.propagate = False
    access_logger.handlers.clear()

    access_handler = logging.StreamHandler(sys.stdout)
    access_handler.setFormatter(formatter)
    access_handler.setLevel(resolved_access_level)
    if suppress_health_logs:
        access_handler.addFilter(HealthLogFilter())
    access_logger.addHandler(access_handler)

    # ── Audit logger — security events (stdout + optional file) ──────────
    audit_logger = logging.getLogger("github_sts.audit")
    audit_logger.setLevel(logging.INFO)  # audit always at INFO+
    audit_logger.propagate = False
    audit_logger.handlers.clear()

    # Audit → stdout (always, for kubectl logs)
    audit_stdout = logging.StreamHandler(sys.stdout)
    audit_stdout.setFormatter(formatter)
    audit_stdout.setLevel(logging.INFO)
    audit_logger.addHandler(audit_stdout)

    # Audit → rotating file (for Promtail / log aggregator)
    if audit_file_enabled:
        audit_dir = Path(audit_file_path).parent
        try:
            audit_dir.mkdir(parents=True, exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                audit_file_path,
                maxBytes=audit_file_max_bytes,
                backupCount=audit_file_backup_count,
            )
            file_handler.setFormatter(formatter)
            file_handler.setLevel(logging.INFO)
            audit_logger.addHandler(file_handler)
        except OSError:
            # Running without write access (e.g. dev / CI) — skip
            logging.getLogger("github_sts").warning(
                "Audit log file disabled: cannot write to %s",
                audit_file_path,
            )

    # ── Silence noisy third-party loggers ────────────────────────────────
    for noisy in ("uvicorn", "uvicorn.access", "httpx", "httpcore"):
        noisy_logger = logging.getLogger(noisy)
        noisy_logger.setLevel(logging.WARNING)
        noisy_logger.propagate = True
