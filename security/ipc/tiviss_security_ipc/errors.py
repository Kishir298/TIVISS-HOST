"""Errors raised by the T.I.V.I.S.S. security IPC layer."""

from __future__ import annotations


class IPCError(Exception):
    """A transport-level failure (path, bind, connect, permissions)."""
