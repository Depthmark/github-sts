"""
Trust Policy model and claim evaluation.

A trust policy looks like (YAML):

  issuer: https://token.actions.githubusercontent.com
  subject: repo:org/repo:ref:refs/heads/main
  permissions:
    contents: read
    issues: write

Or with regex patterns:

  issuer: https://accounts.google.com
  subject_pattern: "[0-9]+"
  claim_pattern:
    email: ".*@example\\.com"
  permissions:
    contents: read
"""

import logging
import re
from typing import Any

from pydantic import BaseModel, field_validator

logger = logging.getLogger(__name__)

# All permissions octo-sts style apps support (subset of GitHub App permissions)
VALID_PERMISSIONS = {
    # Repository
    "actions",
    "checks",
    "contents",
    "deployments",
    "environments",
    "issues",
    "packages",
    "pages",
    "pull_requests",
    "repository_projects",
    "secret_scanning_alerts",
    "secrets",
    "security_events",
    "statuses",
    "vulnerability_alerts",
    "workflows",
    # Organisation
    "members",
    "organization_administration",
    "organization_hooks",
    "organization_packages",
    "organization_plan",
    "organization_projects",
    "organization_secrets",
    "organization_self_hosted_runners",
    "organization_user_blocking",
    "team_discussions",
    # Account
    "blocking",
    "codespaces_user_secrets",
    "email",
    "followers",
    "gpg_keys",
    "gists",
    "git_ssh_keys",
    "interaction_limits",
    "notifications",
    "profile",
    "ssh_signing_keys",
    "starring",
    "watching",
}

VALID_PERMISSION_VALUES = {"read", "write", "admin"}


class TrustPolicy(BaseModel):
    """Parsed and validated trust policy."""

    # Exact-match fields
    issuer: str
    subject: str | None = None
    audience: str | None = None  # expected OIDC aud claim

    # Regex-match fields (used when exact fields absent)
    subject_pattern: str | None = None
    claim_pattern: dict[str, str] | None = None  # arbitrary claim → regex

    # Permissions to grant if policy is satisfied
    permissions: dict[str, str]

    @field_validator("permissions")
    @classmethod
    def validate_permissions(cls, v: dict[str, str]) -> dict[str, str]:
        for perm, level in v.items():
            if perm not in VALID_PERMISSIONS:
                raise ValueError(f"Unknown permission: {perm!r}")
            if level not in VALID_PERMISSION_VALUES:
                raise ValueError(f"Invalid permission level {level!r} for {perm!r}")
        return v

    def evaluate(self, claims: dict[str, Any]) -> bool:
        """
        Return True if the provided JWT claims satisfy this trust policy.

        Evaluation order:
          1. issuer          — must match exactly
          2. subject         — exact match (if set)
          3. subject_pattern — regex match (if subject not set)
          4. claim_pattern   — all regex patterns must match
        """
        logger.debug(
            "Evaluating policy: issuer=%s subject=%s subject_pattern=%s claim_patterns=%s",
            self.issuer,
            self.subject,
            self.subject_pattern,
            list(self.claim_pattern.keys()) if self.claim_pattern else None,
        )

        # 1. Issuer (always exact)
        if claims.get("iss") != self.issuer:
            logger.debug(
                "issuer mismatch: expected %s got %s", self.issuer, claims.get("iss")
            )
            return False

        # 2. Subject — exact match takes priority
        if self.subject is not None:
            if claims.get("sub") != self.subject:
                logger.debug(
                    "subject mismatch: expected %s got %s",
                    self.subject,
                    claims.get("sub"),
                )
                return False
        elif self.subject_pattern is not None:
            if not re.fullmatch(self.subject_pattern, claims.get("sub", "")):
                logger.debug(
                    "subject_pattern %r did not match %r",
                    self.subject_pattern,
                    claims.get("sub"),
                )
                return False

        # 3. Additional claim patterns
        if self.claim_pattern:
            for claim_name, pattern in self.claim_pattern.items():
                value = str(claims.get(claim_name, ""))
                if not re.fullmatch(pattern, value):
                    logger.debug(
                        "claim_pattern %r=%r did not match value %r",
                        claim_name,
                        pattern,
                        value,
                    )
                    return False

        logger.debug("Policy evaluation passed")
        return True
