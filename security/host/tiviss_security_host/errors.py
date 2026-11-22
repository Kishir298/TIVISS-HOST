"""Errors for the T.I.V.I.S.S. PDP host."""

from __future__ import annotations


class PolicyError(ValueError):
    """A policy/rule definition is invalid (fails closed at load time)."""


class ServerError(RuntimeError):
    """The PDP daemon could not start or was used incorrectly."""
