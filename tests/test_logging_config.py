"""
Tests for the structured multi-channel logging configuration.
"""

import json
import logging
import logging.handlers
import tempfile

import pytest

from github_sts.logging_config import HealthLogFilter, JSONFormatter, setup_logging


class TestJSONFormatter:
    """Unit tests for the JSONFormatter and its log_channel derivation."""

    def test_app_channel_for_generic_logger(self):
        """Intention: verify that loggers under github_sts.* get log_channel 'app'.

        What is being tested:
        - JSONFormatter maps logger names not explicitly listed in CHANNEL_MAP
          to the 'app' channel.

        Expected output:
        - JSON output contains ``"log_channel": "app"``.
        """
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="github_sts.routes.exchange",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="test message",
            args=(),
            exc_info=None,
        )
        output = json.loads(formatter.format(record))

        assert output["log_channel"] == "app"
        assert output["message"] == "test message"
        assert output["level"] == "INFO"
        assert "timestamp" in output
        assert "trace_id" in output

    def test_access_channel(self):
        """Intention: verify that github_sts.access maps to log_channel 'access'.

        What is being tested:
        - The CHANNEL_MAP explicit entry for the access logger.

        Expected output:
        - ``"log_channel": "access"``.
        """
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="github_sts.access",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="GET /sts/exchange 200",
            args=(),
            exc_info=None,
        )
        output = json.loads(formatter.format(record))
        assert output["log_channel"] == "access"

    def test_audit_channel(self):
        """Intention: verify that github_sts.audit maps to log_channel 'audit'.

        What is being tested:
        - The CHANNEL_MAP explicit entry for the audit logger.

        Expected output:
        - ``"log_channel": "audit"``.
        """
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="github_sts.audit",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="success",
            args=(),
            exc_info=None,
        )
        output = json.loads(formatter.format(record))
        assert output["log_channel"] == "audit"

    def test_extra_fields_merged_into_json(self):
        """Intention: verify that extra kwargs are merged at the top level.

        What is being tested:
        - Fields passed via ``extra={}`` appear at the top level of the JSON,
          not nested under an ``extra`` key.

        Expected output:
        - ``"method": "POST"`` appears at the top level of parsed JSON.
        """
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="github_sts.access",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="POST /sts/exchange 200",
            args=(),
            exc_info=None,
        )
        record.method = "POST"
        record.path = "/sts/exchange"
        record.status_code = 200

        output = json.loads(formatter.format(record))
        assert output["method"] == "POST"
        assert output["path"] == "/sts/exchange"
        assert output["status_code"] == 200


class TestHealthLogFilter:
    """Unit tests for the health/ready/metrics access log filter."""

    @pytest.fixture()
    def health_filter(self):
        return HealthLogFilter()

    def _make_record(self, path: str, level: int = logging.INFO) -> logging.LogRecord:
        record = logging.LogRecord(
            name="github_sts.access",
            level=level,
            pathname="",
            lineno=0,
            msg=f"GET {path} 200",
            args=(),
            exc_info=None,
        )
        record.path = path
        return record

    def test_suppresses_health_at_info(self, health_filter):
        """Intention: verify health probes are suppressed at INFO level."""
        assert health_filter.filter(self._make_record("/health")) is False

    def test_suppresses_ready_at_info(self, health_filter):
        """Intention: verify readiness probes are suppressed at INFO level."""
        assert health_filter.filter(self._make_record("/ready")) is False

    def test_suppresses_healthz_at_info(self, health_filter):
        """Intention: verify /healthz probes are suppressed at INFO level."""
        assert health_filter.filter(self._make_record("/healthz")) is False

    def test_suppresses_metrics_at_info(self, health_filter):
        """Intention: verify /metrics endpoint is suppressed at INFO level."""
        assert health_filter.filter(self._make_record("/metrics")) is False

    def test_passes_health_at_debug(self, health_filter):
        """Intention: verify health probes pass at DEBUG level."""
        assert health_filter.filter(self._make_record("/health", logging.DEBUG)) is True

    def test_passes_exchange_at_info(self, health_filter):
        """Intention: verify non-probe paths are never suppressed."""
        assert health_filter.filter(self._make_record("/sts/exchange")) is True

    def test_passes_record_without_path(self, health_filter):
        """Intention: verify records without a path attribute pass through."""
        record = logging.LogRecord(
            name="github_sts.access",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="test",
            args=(),
            exc_info=None,
        )
        # No record.path set
        assert health_filter.filter(record) is True


class TestSetupLogging:
    """Integration tests for the setup_logging() function."""

    def _cleanup_loggers(self):
        """Reset loggers to avoid cross-test pollution."""
        for name in ("github_sts", "github_sts.access", "github_sts.audit"):
            lgr = logging.getLogger(name)
            lgr.handlers.clear()
            lgr.setLevel(logging.WARNING)
            lgr.propagate = True

    def test_creates_three_loggers(self):
        """Intention: verify that setup_logging configures three separate loggers.

        What is being tested:
        - After calling setup_logging(), the github_sts, github_sts.access,
          and github_sts.audit loggers each have handlers and propagate=False.

        Expected output:
        - Each logger has at least one handler.
        - propagate is False on all three.
        """
        try:
            setup_logging(
                level="INFO",
                audit_file_enabled=False,
            )

            app_logger = logging.getLogger("github_sts")
            access_logger = logging.getLogger("github_sts.access")
            audit_logger = logging.getLogger("github_sts.audit")

            assert len(app_logger.handlers) >= 1
            assert len(access_logger.handlers) >= 1
            assert len(audit_logger.handlers) >= 1

            assert app_logger.propagate is False
            assert access_logger.propagate is False
            assert audit_logger.propagate is False
        finally:
            self._cleanup_loggers()

    def test_audit_file_handler_created(self):
        """Intention: verify RotatingFileHandler is added for audit when enabled.

        What is being tested:
        - When audit_file_enabled=True and a writable path is given, a
          RotatingFileHandler is added to the audit logger.

        Expected output:
        - The audit logger has at least 2 handlers (stdout + file).
        - One of them is a RotatingFileHandler.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                audit_path = f"{tmpdir}/audit.json"
                setup_logging(
                    level="INFO",
                    audit_file_enabled=True,
                    audit_file_path=audit_path,
                )

                audit_logger = logging.getLogger("github_sts.audit")
                assert len(audit_logger.handlers) >= 2

                file_handlers = [
                    h
                    for h in audit_logger.handlers
                    if isinstance(h, logging.handlers.RotatingFileHandler)
                ]
                assert len(file_handlers) == 1
            finally:
                self._cleanup_loggers()

    def test_audit_file_handler_skipped_when_disabled(self):
        """Intention: verify no file handler when audit_file_enabled=False.

        What is being tested:
        - When disabled, the audit logger only has the stdout handler.

        Expected output:
        - The audit logger has exactly 1 handler (stdout only).
        """
        try:
            setup_logging(
                level="INFO",
                audit_file_enabled=False,
            )

            audit_logger = logging.getLogger("github_sts.audit")
            file_handlers = [
                h
                for h in audit_logger.handlers
                if isinstance(h, logging.handlers.RotatingFileHandler)
            ]
            assert len(file_handlers) == 0
        finally:
            self._cleanup_loggers()

    def test_health_filter_applied_when_enabled(self):
        """Intention: verify HealthLogFilter is on the access handler.

        What is being tested:
        - When suppress_health_logs=True, the access handler has a HealthLogFilter.

        Expected output:
        - At least one filter on the access handler is a HealthLogFilter.
        """
        try:
            setup_logging(
                level="INFO",
                suppress_health_logs=True,
                audit_file_enabled=False,
            )

            access_logger = logging.getLogger("github_sts.access")
            handler = access_logger.handlers[0]
            filter_types = [type(f) for f in handler.filters]
            assert HealthLogFilter in filter_types
        finally:
            self._cleanup_loggers()

    def test_health_filter_not_applied_when_disabled(self):
        """Intention: verify HealthLogFilter is absent when disabled.

        What is being tested:
        - When suppress_health_logs=False, no HealthLogFilter is added.

        Expected output:
        - No filter on the access handler is a HealthLogFilter.
        """
        try:
            setup_logging(
                level="INFO",
                suppress_health_logs=False,
                audit_file_enabled=False,
            )

            access_logger = logging.getLogger("github_sts.access")
            handler = access_logger.handlers[0]
            filter_types = [type(f) for f in handler.filters]
            assert HealthLogFilter not in filter_types
        finally:
            self._cleanup_loggers()

    def test_child_logger_propagates_to_app(self):
        """Intention: verify child loggers of github_sts propagate to app handler.

        What is being tested:
        - A logger like github_sts.routes.exchange inherits from github_sts
          and its output is handled by the app channel handler.

        Expected output:
        - The child logger's effective level matches the app logger's level.
        """
        try:
            setup_logging(
                level="DEBUG",
                audit_file_enabled=False,
            )

            child = logging.getLogger("github_sts.routes.exchange")
            assert child.getEffectiveLevel() == logging.DEBUG
        finally:
            self._cleanup_loggers()

    def test_noisy_loggers_silenced(self):
        """Intention: verify third-party loggers are set to WARNING.

        Expected output:
        - uvicorn, httpx, httpcore loggers are at WARNING level.
        """
        try:
            setup_logging(level="INFO", audit_file_enabled=False)

            for name in ("uvicorn", "uvicorn.access", "httpx", "httpcore"):
                assert logging.getLogger(name).level >= logging.WARNING
        finally:
            self._cleanup_loggers()
