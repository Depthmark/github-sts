"""
Tests for trust policy evaluation.
Run with: pytest tests/
"""

import pytest

from github_sts.policy import TrustPolicy


class TestTrustPolicyExactMatch:
    """Unit tests for exact issuer and subject matching rules."""

    def _policy(self, **kwargs):
        """Create a valid baseline policy and allow targeted overrides per test."""
        base = {
            "issuer": "https://token.actions.githubusercontent.com",
            "subject": "repo:org/repo:ref:refs/heads/main",
            "permissions": {"contents": "read"},
        }
        base.update(kwargs)
        return TrustPolicy(**base)

    def test_exact_match_passes(self):
        """Intention: verify matching issuer and subject are accepted.

        What is being tested:
        - `TrustPolicy.evaluate()` for an exact-match policy with valid claims.

        Expected output:
        - The evaluation result is `True`.
        """
        policy = self._policy()
        claims = {
            "iss": "https://token.actions.githubusercontent.com",
            "sub": "repo:org/repo:ref:refs/heads/main",
        }
        assert policy.evaluate(claims) is True

    def test_wrong_issuer_denied(self):
        """Intention: verify issuer mismatches are denied immediately.

        What is being tested:
        - `evaluate()` rejects claims with an unexpected `iss` value.

        Expected output:
        - The evaluation result is `False`.
        """
        policy = self._policy()
        claims = {
            "iss": "https://evil.example.com",
            "sub": "repo:org/repo:ref:refs/heads/main",
        }
        assert policy.evaluate(claims) is False

    def test_wrong_subject_denied(self):
        """Intention: verify subject mismatches are denied for exact policies.

        What is being tested:
        - `evaluate()` compares `sub` exactly when `subject` is configured.

        Expected output:
        - The evaluation result is `False`.
        """
        policy = self._policy()
        claims = {
            "iss": "https://token.actions.githubusercontent.com",
            "sub": "repo:org/repo:ref:refs/heads/develop",
        }
        assert policy.evaluate(claims) is False


class TestTrustPolicyPatterns:
    """Unit tests for regex-based subject and claim matching."""

    def test_subject_pattern_matches(self):
        """Intention: verify regex subject matching accepts only valid subjects.

        What is being tested:
        - `subject_pattern` is evaluated with full regex matching.

        Expected output:
        - Numeric subjects are accepted.
        - Non-numeric subjects are rejected.
        """
        policy = TrustPolicy(
            issuer="https://accounts.google.com",
            subject_pattern=r"[0-9]+",
            permissions={"contents": "read"},
        )
        assert policy.evaluate(
            {"iss": "https://accounts.google.com", "sub": "1234567890"}
        )
        assert not policy.evaluate(
            {"iss": "https://accounts.google.com", "sub": "not-a-number"}
        )

    def test_claim_pattern_matches(self):
        """Intention: verify additional claim regexes refine access decisions.

        What is being tested:
        - `claim_pattern` must match all configured claims.

        Expected output:
        - A matching email domain is accepted.
        - A non-matching domain is rejected.
        """
        policy = TrustPolicy(
            issuer="https://accounts.google.com",
            subject_pattern=r"[0-9]+",
            claim_pattern={"email": r".*@example\.com"},
            permissions={"contents": "read"},
        )
        good = {
            "iss": "https://accounts.google.com",
            "sub": "123",
            "email": "dev@example.com",
        }
        bad = {
            "iss": "https://accounts.google.com",
            "sub": "123",
            "email": "dev@evil.com",
        }
        assert policy.evaluate(good)
        assert not policy.evaluate(bad)

    def test_exact_subject_takes_priority_over_pattern(self):
        """Intention: verify exact subjects override broader regex patterns.

        What is being tested:
        - When both `subject` and `subject_pattern` are present, exact subject
          matching is authoritative.

        Expected output:
        - A claim matching only the regex is still rejected.
        """
        policy = TrustPolicy(
            issuer="https://token.actions.githubusercontent.com",
            subject="repo:org/repo:ref:refs/heads/main",
            subject_pattern=r".*",  # would match anything, but subject wins
            permissions={"issues": "write"},
        )
        claims = {
            "iss": "https://token.actions.githubusercontent.com",
            "sub": "repo:org/repo:ref:refs/heads/develop",
        }
        assert not policy.evaluate(claims)

    def test_workflow_ref_claim_pattern(self):
        """Intention: verify workflow-level restrictions for GitHub Actions.

        What is being tested:
        - `job_workflow_ref` claim matching can restrict access to one workflow.

        Expected output:
        - The trusted workflow is accepted.
        - An untrusted workflow file is rejected.
        """
        policy = TrustPolicy(
            issuer="https://token.actions.githubusercontent.com",
            subject_pattern=r"repo:org/repo:.*",
            claim_pattern={
                "job_workflow_ref": r"org/repo/.github/workflows/deploy\.yml@.*"
            },
            permissions={"deployments": "write"},
        )
        good = {
            "iss": "https://token.actions.githubusercontent.com",
            "sub": "repo:org/repo:ref:refs/heads/main",
            "job_workflow_ref": "org/repo/.github/workflows/deploy.yml@refs/heads/main",
        }
        bad = {
            "iss": "https://token.actions.githubusercontent.com",
            "sub": "repo:org/repo:ref:refs/heads/main",
            "job_workflow_ref": "org/repo/.github/workflows/untrusted.yml@refs/heads/main",
        }
        assert policy.evaluate(good)
        assert not policy.evaluate(bad)


class TestPolicyValidation:
    """Unit tests for trust policy schema validation."""

    def test_invalid_permission_name_rejected(self):
        """Intention: verify unsupported GitHub permissions are rejected.

        What is being tested:
        - Pydantic validation rejects unknown permission names.

        Expected output:
        - Policy construction raises a validation-related exception.
        """
        with pytest.raises((ValueError, Exception)):
            TrustPolicy(
                issuer="https://example.com",
                permissions={"nonexistent_permission": "read"},
            )

    def test_invalid_permission_level_rejected(self):
        """Intention: verify unsupported permission levels are rejected.

        What is being tested:
        - Validation enforces the allowed levels: `read`, `write`, `admin`.

        Expected output:
        - Policy construction raises a validation-related exception.
        """
        with pytest.raises((ValueError, Exception)):
            TrustPolicy(
                issuer="https://example.com",
                permissions={"contents": "superadmin"},
            )

    def test_multiple_permissions_accepted(self):
        """Intention: verify valid multi-permission policies are preserved.

        What is being tested:
        - A policy can carry several valid GitHub permissions at once.

        Expected output:
        - Policy construction succeeds and all three permissions remain present.
        """
        policy = TrustPolicy(
            issuer="https://token.actions.githubusercontent.com",
            subject="repo:org/repo:ref:refs/heads/main",
            permissions={
                "contents": "read",
                "issues": "write",
                "pull_requests": "write",
            },
        )
        assert len(policy.permissions) == 3
