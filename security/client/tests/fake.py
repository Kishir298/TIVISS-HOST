"""Test helper: a minimal fake daemon that answers with a canned envelope."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from tiviss_security_ipc import Channel, prepare_listener, unlink_socket

Handler = Callable[[dict[str, Any]], dict[str, Any]]


@contextmanager
def fake_server(path: str | Path, handler: Handler) -> Iterator[None]:
    """Serve one canned response per request until the context exits."""
    listener = prepare_listener(path)

    def serve() -> None:
        while True:
            try:
                conn, _addr = listener.accept()
            except OSError:
                return
            with Channel(conn) as channel:
                try:
                    request = channel.recv()
                except Exception:
                    continue
                channel.send(handler(request))

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield
    finally:
        listener.close()
        unlink_socket(path)
        thread.join(timeout=2)
