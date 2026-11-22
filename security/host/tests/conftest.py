"""Shared fixtures for the PDP host test suite."""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture()
def sock_dir() -> Iterator[Path]:
    """Short directory for bind tests (AF_UNIX paths cap at ~104 bytes)."""
    path = Path(tempfile.mkdtemp(prefix="tsec-", dir="/tmp"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)
