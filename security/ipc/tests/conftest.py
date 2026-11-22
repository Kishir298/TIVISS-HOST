"""Shared fixtures for the ipc test suite."""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture()
def sock_dir() -> Iterator[Path]:
    """Short directory for bind tests.

    ``AF_UNIX`` socket paths are limited to ~104 bytes on macOS, which the
    default ``tmp_path`` prefix easily exceeds; ``/tmp`` keeps paths short.
    """
    path = Path(tempfile.mkdtemp(prefix="tsec-", dir="/tmp"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)
