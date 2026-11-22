"""Request/response conversations over a socket using protocol framing."""

from __future__ import annotations

import contextlib
import socket
from collections.abc import Mapping
from typing import Any

from tiviss_security_protocol import read_frame, send_frame

from .uds import DEFAULT_CONNECT_TIMEOUT, connect


class Channel:
    """One conversation over a connected socket (protocol envelopes)."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._closed = False

    @classmethod
    def connect(
        cls, path, *, timeout: float | None = DEFAULT_CONNECT_TIMEOUT
    ) -> Channel:
        return cls(connect(path, timeout=timeout))

    @property
    def sock(self) -> socket.socket:
        return self._sock

    def send(self, message: Mapping[str, Any]) -> int:
        """Send one envelope; returns the frame byte count."""
        return send_frame(self._sock.sendall, message)

    def recv(self) -> dict[str, Any]:
        """Receive one envelope (``FrameError`` on malformed input)."""
        return read_frame(self._sock.recv)

    def request(
        self, message: Mapping[str, Any], *, timeout: float | None = None
    ) -> dict[str, Any]:
        """Send one envelope and wait for the response envelope."""
        if timeout is not None:
            self._sock.settimeout(timeout)
        self.send(message)
        return self.recv()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(OSError):
            self._sock.close()

    @property
    def closed(self) -> bool:
        return self._closed

    def __enter__(self) -> Channel:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def request_once(
    path,
    message: Mapping[str, Any],
    *,
    timeout: float | None = DEFAULT_CONNECT_TIMEOUT,
) -> dict[str, Any]:
    """One-shot ``connect -> send -> recv -> close`` conversation."""
    with Channel.connect(path, timeout=timeout) as channel:
        return channel.request(message, timeout=timeout)


__all__ = ["Channel", "request_once"]
