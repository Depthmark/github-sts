"""
Tests for structured audit logging.
"""

import json
import tempfile

import pytest

from github_sts.audit import (
    AuditEvent,
    ExchangeResult,
    FileAuditLogger,
    create_audit_logger,
)


class TestAuditEvent:
    """Unit tests for the `AuditEvent` model and its JSON serialization."""

    def test_audit_event_creation(self):
        """Intention: verify the minimal success payload is accepted.

        What is being tested:
        - `AuditEvent` accepts the required fields for a successful exchange.
        - The model auto-populates `timestamp`.

        Expected output:
        - The event keeps the provided `scope`, `identity`, and `result`.
        - `timestamp` is populated with a non-empty value.
        """
        event = AuditEvent(
            scope="owner/repo",
            identity="ci",
            issuer="https://token.actions.githubusercontent.com",
            subject="repo:owner/repo:ref:refs/heads/main",
            result=ExchangeResult.SUCCESS,
        )

        assert event.scope == "owner/repo"
        assert event.identity == "ci"
        assert event.result == ExchangeResult.SUCCESS
        assert event.timestamp is not None

    def test_audit_event_with_all_fields(self):
        """Intention: verify optional metadata survives model construction.

        What is being tested:
        - `AuditEvent` accepts optional timing and client context fields.

        Expected output:
        - Optional fields are stored exactly as provided.
        """
        event = AuditEvent(
            scope="owner/repo",
            identity="ci",
            issuer="https://token.actions.githubusercontent.com",
            subject="repo:owner/repo:ref:refs/heads/main",
            jti="workflow-123",
            result=ExchangeResult.SUCCESS,
            error_reason=None,
            duration_ms=150.5,
            user_agent="github-actions/v1",
            remote_ip="192.168.1.1",
        )

        assert event.duration_ms == 150.5
        assert event.user_agent == "github-actions/v1"
        assert event.remote_ip == "192.168.1.1"

    def test_audit_event_denied(self):
        """Intention: verify denied exchanges can carry a failure reason.

        What is being tested:
        - A non-success `ExchangeResult` can be paired with `error_reason`.

        Expected output:
        - The event result is `policy_denied` and the reason is preserved.
        """
        event = AuditEvent(
            scope="owner/repo",
            identity="ci",
            issuer="https://token.actions.githubusercontent.com",
            subject="untrusted-subject",
            result=ExchangeResult.POLICY_DENIED,
            error_reason="Subject does not match policy",
        )

        assert event.result == ExchangeResult.POLICY_DENIED
        assert event.error_reason is not None

    def test_audit_event_to_json_line(self):
        """Intention: verify JSON-Lines serialization is newline-delimited.

        What is being tested:
        - `AuditEvent.to_json_line()` returns valid JSON plus a trailing newline.
        - Enum values are serialized as their string values.

        Expected output:
        - The serialized string ends with `\n`.
        - Decoded JSON contains the original values and `result == "success"`.
        """
        event = AuditEvent(
            scope="owner/repo",
            identity="ci",
            issuer="https://github.com",
            subject="ghsa",
            result=ExchangeResult.SUCCESS,
        )

        line = event.to_json_line()
        assert line.endswith("\n")

        # Parse JSON
        parsed = json.loads(line.rstrip("\n"))
        assert parsed["scope"] == "owner/repo"
        assert parsed["identity"] == "ci"
        assert parsed["result"] == "success"


class TestFileAuditLogger:
    """Unit tests for the asynchronous file-backed audit logger."""

    @pytest.mark.asyncio
    async def test_file_logger_creation(self):
        """Intention: verify the logger initializes with sane defaults.

        What is being tested:
        - `FileAuditLogger` stores the target path and default rotation policy.

        Expected output:
        - The file name is `audit.log` and the default policy is `daily`.
        - Cleanup completes without error.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = f"{tmpdir}/audit.log"
            logger = FileAuditLogger(log_path=log_path)

            assert logger.log_path.name == "audit.log"
            assert logger.rotation_policy == "daily"
            await logger.cleanup()

    @pytest.mark.asyncio
    async def test_file_logger_write_event(self):
        """Intention: verify one queued event is flushed to disk.

        What is being tested:
        - `log_event()` writes a serialized audit record to the file.

        Expected output:
        - The log file exists, contains at least one line of JSON, and the
          first record contains the original `scope` value.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = f"{tmpdir}/audit.log"
            logger = FileAuditLogger(log_path=log_path)

            event = AuditEvent(
                scope="owner/repo",
                identity="ci",
                issuer="https://github.com",
                subject="test",
                result=ExchangeResult.SUCCESS,
            )

            await logger.log_event(event)
            await logger.cleanup()

            with open(log_path) as f:
                content = f.read()
                assert len(content) > 0
                lines = content.strip().split("\n")
                assert len(lines) >= 1

                parsed = json.loads(lines[0])
                assert parsed["scope"] == "owner/repo"

    @pytest.mark.asyncio
    async def test_file_logger_multiple_events(self):
        """Intention: verify event ordering is preserved for multiple writes.

        What is being tested:
        - Repeated `log_event()` calls append one JSON line per event.

        Expected output:
        - At least five lines are written.
        - The first five lines keep the scopes in the same order they were queued.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = f"{tmpdir}/audit.log"
            logger = FileAuditLogger(log_path=log_path)

            # Log multiple events
            for i in range(5):
                event = AuditEvent(
                    scope=f"repo{i}",
                    identity=f"identity{i}",
                    issuer="https://github.com",
                    subject=f"subject{i}",
                    result=ExchangeResult.SUCCESS,
                )
                await logger.log_event(event)

            await logger.cleanup()

            # Verify all events written
            with open(log_path) as f:
                lines = [line for line in f.read().strip().split("\n") if line]
                assert len(lines) >= 5

                for i, line in enumerate(lines[:5]):
                    parsed = json.loads(line)
                    assert parsed["scope"] == f"repo{i}"

    @pytest.mark.asyncio
    async def test_file_logger_daily_rotation(self):
        """Intention: verify daily rotation can be configured explicitly.

        What is being tested:
        - Constructor wiring for the `daily` rotation mode.

        Expected output:
        - `rotation_policy` is stored as `daily`.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = f"{tmpdir}/audit.log"
            logger = FileAuditLogger(log_path=log_path, rotation_policy="daily")

            assert logger.rotation_policy == "daily"
            await logger.cleanup()

    @pytest.mark.asyncio
    async def test_file_logger_size_rotation(self):
        """Intention: verify size-based rotation settings are preserved.

        What is being tested:
        - Constructor wiring for `size` rotation and custom thresholds.

        Expected output:
        - `rotation_policy` is `size`.
        - `rotation_size_bytes` matches the provided threshold.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = f"{tmpdir}/audit.log"
            logger = FileAuditLogger(
                log_path=log_path,
                rotation_policy="size",
                rotation_size_bytes=1000,
            )

            assert logger.rotation_policy == "size"
            assert logger.rotation_size_bytes == 1000
            await logger.cleanup()


class TestCreateAuditLogger:
    """Unit tests for the audit logger factory function."""

    @pytest.mark.asyncio
    async def test_create_file_logger(self):
        """Intention: verify the factory resolves the file backend correctly.

        What is being tested:
        - `create_audit_logger("file", ...)` returns a `FileAuditLogger`.

        Expected output:
        - The returned object is an instance of `FileAuditLogger`.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = await create_audit_logger("file", log_path=f"{tmpdir}/audit.log")
            assert isinstance(logger, FileAuditLogger)
            await logger.cleanup()

    @pytest.mark.asyncio
    async def test_create_invalid_backend(self):
        """Intention: verify unsupported backends fail fast.

        What is being tested:
        - The factory rejects unknown backend names.

        Expected output:
        - A `ValueError` is raised with an explanatory message.
        """
        with pytest.raises(ValueError, match="Unknown audit logger backend"):
            await create_audit_logger("invalid-backend")


class TestAuditEventResults:
    """Coverage checks for every supported `ExchangeResult` value."""

    def test_all_result_types(self):
        """Intention: verify every exchange outcome can be serialized safely.

        What is being tested:
        - Each `ExchangeResult` enum member is accepted by `AuditEvent`.
        - Serialization emits the enum's string value.

        Expected output:
        - Event creation succeeds for every enum member.
        - Serialized JSON exposes the exact enum value string.
        """
        results = [
            ExchangeResult.SUCCESS,
            ExchangeResult.POLICY_DENIED,
            ExchangeResult.OIDC_INVALID,
            ExchangeResult.JTI_REPLAY,
            ExchangeResult.POLICY_NOT_FOUND,
            ExchangeResult.CACHE_ERROR,
            ExchangeResult.GITHUB_ERROR,
            ExchangeResult.UNKNOWN_ERROR,
        ]

        for result in results:
            event = AuditEvent(
                scope="test",
                identity="test",
                issuer="https://github.com",
                subject="test",
                result=result,
            )
            assert event.result == result

            # Verify JSON serialization
            line = event.to_json_line()
            parsed = json.loads(line.rstrip("\n"))
            assert parsed["result"] == result.value


class TestAuditIntegration:
    """Integration-style tests covering realistic audit log flows."""

    @pytest.mark.asyncio
    async def test_realistic_audit_flow(self):
        """Intention: verify mixed exchange outcomes are persisted together.

        What is being tested:
        - The logger can persist both successful and denied exchanges.
        - Serialized output preserves each event's result and scope.

        Expected output:
        - Two JSON lines are present.
        - The first record is a success for `owner/repo`.
        - The second record is a denial for `owner/private`.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = f"{tmpdir}/audit.log"
            logger = FileAuditLogger(log_path=log_path)

            # Simulate exchange flow with multiple events
            events = [
                AuditEvent(
                    scope="owner/repo",
                    identity="ci",
                    issuer="https://token.actions.githubusercontent.com",
                    subject="repo:owner/repo:ref:refs/heads/main",
                    jti="workflow-123",
                    result=ExchangeResult.SUCCESS,
                    duration_ms=145.25,
                    user_agent="github-actions/v1",
                    remote_ip="192.0.2.1",
                ),
                AuditEvent(
                    scope="owner/private",
                    identity="ci",
                    issuer="https://token.actions.githubusercontent.com",
                    subject="fork:attacker/repo:ref:refs/heads/main",
                    result=ExchangeResult.POLICY_DENIED,
                    error_reason="Subject does not match allowed patterns",
                    duration_ms=50.1,
                    user_agent="curl/7.68.0",
                    remote_ip="198.51.100.1",
                ),
            ]

            for event in events:
                await logger.log_event(event)

            await logger.cleanup()

            # Verify file structure
            with open(log_path) as f:
                lines = [line for line in f.read().strip().split("\n") if line]
                assert len(lines) >= 2

                # First event should be success
                first = json.loads(lines[0])
                assert first["result"] == "success"
                assert first["scope"] == "owner/repo"

                # Second event should be denied
                second = json.loads(lines[1])
                assert second["result"] == "policy_denied"
                assert second["scope"] == "owner/private"

    @pytest.mark.asyncio
    async def test_json_lines_compatibility(self):
        """Intention: verify the file output is consumable as JSON Lines.

        What is being tested:
        - Every line written by the logger is valid standalone JSON.

        Expected output:
        - Each line parses cleanly and contains the core keys used by
          downstream tooling: `scope` and `result`.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = f"{tmpdir}/audit.log"
            logger = FileAuditLogger(log_path=log_path)

            for i in range(3):
                event = AuditEvent(
                    scope=f"repo{i}",
                    identity="ci",
                    issuer="https://github.com",
                    subject=f"subject{i}",
                    result=ExchangeResult.SUCCESS,
                )
                await logger.log_event(event)

            await logger.cleanup()

            with open(log_path) as f:
                for line in f:
                    parsed = json.loads(line)
                    assert "scope" in parsed
                    assert "result" in parsed
