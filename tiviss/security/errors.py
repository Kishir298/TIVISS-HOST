"""Errors for the T.I.V.I.S.S. security facade."""

from __future__ import annotations


class SecurityError(Exception):
    """Base class for security-facade failures."""


class SecurityConfigurationError(SecurityError):
    """The security configuration is invalid (fail closed at startup)."""


class SecurityUnavailableError(SecurityError):
    """The policy decision point could not be reached (fail closed)."""
