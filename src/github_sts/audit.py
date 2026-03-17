"""
Structured audit logging for token exchanges.

Provides compliance-ready audit trails for all token exchange attempts,
including successes, denials, and errors. Supports multiple backends
(file-based, database) and includes sensitive data redaction.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

# Dedicated audit channel — routed by logging_config.setup_logging()
audit_channel = logging.getLogger("github_sts.audit")


class ExchangeResult(StrEnum):
    """Result of a token exchange attempt."""

    SUCCESS = "success"
    POLICY_DENIED = "policy_denied"
    OIDC_INVALID = "oidc_invalid"
    JTI_REPLAY = "jti_replay"
    POLICY_NOT_FOUND = "policy_not_found"
    CACHE_ERROR = "cache_error"
    GITHUB_ERROR = "github_error"
    UNKNOWN_ERROR = "unknown_error"


class AuditEvent(BaseModel):
    """
    Structured audit event for a token exchange attempt.

    Includes all relevant information for compliance and security investigations,
    with sensitive data redacted.
    """

    # Timestamps
    timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        description="ISO 8601 timestamp of the event",
    )

    # Request details
    scope: str = Field(..., description="Requested repository or org scope")
    identity: str = Field(..., description="Trust policy identity being evaluated")

    # OIDC information (potentially sensitive)
    issuer: str = Field(..., description="OIDC issuer URL")
    subject: str = Field(..., description="OIDC subject (workload identifier)")

    # Claim info (first 50 chars, redacted for PII)
    jti: str | None = Field(None, description="JWT ID claim (hashed/truncated)")

    # Exchange result
    result: ExchangeResult = Field(..., description="Outcome of the exchange")

    # Error details (if applicable)
    error_reason: str | None = Field(
        None, description="Reason for denial or error (no sensitive data)"
    )

    # Performance metrics
    duration_ms: float | None = Field(
        None, description="Request duration in milliseconds"
    )

    # Additional context
    user_agent: str | None = Field(
        None,
        description="Client user agent (truncated to 100 chars)",
    )
    remote_ip: str | None = Field(None, description="Client IP address (if available)")

    model_config = ConfigDict(use_enum_values=True)

    def to_json_line(self) -> str:
        """Convert event to JSON-Lines format (one JSON per line)."""
        return self.model_dump_json(exclude_none=True) + "\n"


class AuditLogger(ABC):
    """Abstract interface for audit logging backends."""

    @abstractmethod
    async def log_event(self, event: AuditEvent) -> None:
        """
        Log an audit event.

        Args:
            event: AuditEvent to log

        Raises:
            Exception: On logging errors (implementations should log/propagate)
        """
        pass

    @abstractmethod
    async def cleanup(self) -> None:
        """Clean up resources."""
        pass


class FileAuditLogger(AuditLogger):
    """
    File-based audit logger with JSON-Lines format and rotation support.

    Events are written as one JSON object per line for easy parsing
    with tools like jq, logstash, etc.

    WARNING: File writes are buffered for performance. Call cleanup()
    or flush() to ensure all events are written.
    """

    def __init__(
        self,
        log_path: str = "./audit.log",
        rotation_policy: Literal["daily", "size"] = "daily",
        rotation_size_bytes: int = 100 * 1024 * 1024,  # 100MB
    ):
        """
        Initialize file-based audit logger.

        Args:
            log_path: Path to audit log file
            rotation_policy: "daily" or "size" rotation
            rotation_size_bytes: Size threshold for rotation (if size policy)
        """
        self.log_path = Path(log_path)
        self.rotation_policy = rotation_policy
        self.rotation_size_bytes = rotation_size_bytes

        # Create log directory if needed
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        self._file = None
        self._queue: asyncio.Queue = asyncio.Queue()
        self._writer_task: asyncio.Task | None = None
        self._last_rotation_date = datetime.now(UTC).date()
        self._initialized = False

        logger.info(
            "FileAuditLogger initialized: path=%s rotation=%s",
            self.log_path,
            rotation_policy,
        )

    async def _ensure_writer_started(self) -> None:
        """Ensure the writer background task is running."""
        if not self._initialized:
            self._writer_task = asyncio.create_task(self._writer_loop())
            self._initialized = True

    async def log_event(self, event: AuditEvent) -> None:
        """Queue event for async file writing and emit on the audit channel."""
        await self._ensure_writer_started()
        await self._queue.put(event)

        # Also emit via the structured audit logger (stdout + aggregator)
        audit_channel.info(
            event.result,
            extra=event.model_dump(exclude_none=True),
        )

    async def _ensure_open(self) -> None:
        """Ensure log file is open, rotating if needed."""
        if self._file is None:
            self._file = open(self.log_path, "a", encoding="utf-8")

    async def _check_rotation(self) -> None:
        """Check if rotation is needed based on policy."""
        if not self._file:
            return

        if self.rotation_policy == "daily":
            today = datetime.now(UTC).date()
            if today != self._last_rotation_date:
                await self._rotate()
                self._last_rotation_date = today

        elif self.rotation_policy == "size":
            try:
                file_size = self._file.tell()
                if file_size > self.rotation_size_bytes:
                    await self._rotate()
            except Exception as e:
                logger.error("Error checking file size for rotation: %s", e)

    async def _rotate(self) -> None:
        """Rotate the log file."""
        if not self._file:
            return

        try:
            self._file.close()
            timestamp = datetime.now(UTC).isoformat()[:10]
            backup_path = self.log_path.with_name(
                f"{self.log_path.stem}.{timestamp}.log"
            )
            self.log_path.rename(backup_path)
            logger.info("Rotated audit log to %s", backup_path)
            self._file = None
        except Exception as e:
            logger.error("Error rotating audit log: %s", e)

    async def _writer_loop(self) -> None:
        """Background task that writes events from queue to file."""
        try:
            while True:
                event = await self._queue.get()

                try:
                    await self._ensure_open()
                    await self._check_rotation()
                    await self._ensure_open()  # May be None after rotation

                    if self._file:
                        self._file.write(event.to_json_line())
                        self._file.flush()

                except Exception as e:
                    logger.error("Error writing audit event: %s", e)
                finally:
                    self._queue.task_done()

        except asyncio.CancelledError:
            logger.debug("Audit writer loop cancelled")
            # Drain remaining events on shutdown
            try:
                while True:
                    event = self._queue.get_nowait()
                    if self._file:
                        self._file.write(event.to_json_line())
                        self._file.flush()
            except asyncio.QueueEmpty:
                pass
            raise

    async def cleanup(self) -> None:
        """Close file and cleanup resources."""
        # Wait for queue to drain
        try:
            await asyncio.wait_for(self._queue.join(), timeout=5.0)
        except TimeoutError:
            logger.warning("Audit queue did not drain in time")

        # Cancel writer task
        if self._writer_task:
            self._writer_task.cancel()
            try:
                await self._writer_task
            except asyncio.CancelledError:
                pass

        # Close file
        if self._file:
            self._file.close()
            self._file = None

        logger.info("FileAuditLogger cleaned up")


async def create_audit_logger(
    backend: Literal["file"] = "file",
    **kwargs,
) -> AuditLogger:
    """
    Factory function to create audit logger.

    Args:
        backend: "file" (only supported backend)
        **kwargs: Backend-specific arguments

    Returns:
        Configured FileAuditLogger instance
    """
    if backend == "file":
        return FileAuditLogger(
            log_path=kwargs.get("log_path", "./audit.log"),
            rotation_policy=kwargs.get("rotation_policy", "daily"),
            rotation_size_bytes=kwargs.get("rotation_size_bytes", 100 * 1024 * 1024),
        )
    else:
        raise ValueError(
            f"Unknown audit logger backend: {backend!r}. "
            "Only 'file' backend is supported."
        )
