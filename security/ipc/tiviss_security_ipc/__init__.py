"""Unix-domain-socket transport for the T.I.V.I.S.S. security PDP.

Stdlib-only; built on top of ``tiviss-security-protocol`` framing.
"""

from __future__ import annotations

from .channel import Channel, request_once
from .errors import IPCError
from .uds import (
    SOCKET_ENV,
    PeerCredentials,
    connect,
    peer_credentials,
    prepare_listener,
    resolve_socket_path,
    unlink_socket,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "SOCKET_ENV",
    "IPCError",
    "PeerCredentials",
    "Channel",
    "resolve_socket_path",
    "prepare_listener",
    "connect",
    "peer_credentials",
    "unlink_socket",
    "request_once",
]
