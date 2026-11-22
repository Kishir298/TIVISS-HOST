"""Unix-domain-socket path resolution and listener/client helpers.

Socket path priority:
  1. explicit argument
  2. ``TIVISS_SECURITY_SOCKET`` environment variable
  3. ``/run/tiviss/security.sock`` (when ``/run/tiviss`` exists and is
     writable by the current user)
  4. ``$XDG_RUNTIME_DIR/tiviss/security.sock`` (when set and writable)
  5. ``<temp dir>/tiviss/security.sock`` (portable fallback)

Listener hardening: parent directory is created ``0700`` when we create it,
the socket file is ``0600``, stale socket files are replaced, and any
non-socket path at the target location is refused (fail closed).
"""

from __future__ import annotations

import os
import socket
import stat
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .errors import IPCError

SOCKET_ENV = "TIVISS_SECURITY_SOCKET"
RUN_DIR = Path("/run/tiviss")
SOCKET_NAME = "security.sock"
DEFAULT_BACKLOG = 64
DEFAULT_CONNECT_TIMEOUT = 5.0

_PEERCRED_STRUCT = struct.Struct("3i")


@dataclass(frozen=True)
class PeerCredentials:
    """Identity of the peer process on the other end of a UDS connection."""

    pid: int
    uid: int
    gid: int


def resolve_socket_path(explicit: str | os.PathLike[str] | None = None) -> Path:
    """Resolve the security socket path (see module docstring for order)."""
    if explicit is not None and str(explicit).strip():
        return Path(explicit)
    env = os.environ.get(SOCKET_ENV)
    if env and env.strip():
        return Path(env.strip())
    try:
        if RUN_DIR.is_dir() and os.access(RUN_DIR, os.W_OK):
            return RUN_DIR / SOCKET_NAME
    except OSError:
        pass
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg and xdg.strip():
        xdg_dir = Path(xdg.strip())
        try:
            if xdg_dir.is_dir() and os.access(xdg_dir, os.W_OK):
                return xdg_dir / "tiviss" / SOCKET_NAME
        except OSError:
            pass
    return Path(tempfile.gettempdir()) / "tiviss" / SOCKET_NAME


def unlink_socket(path: str | os.PathLike[str]) -> None:
    """Remove ``path`` when it is a socket file; ignore it when absent."""
    path = Path(path)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise IPCError(f"cannot stat socket path {path}: {exc}") from exc
    if stat.S_ISSOCK(st.st_mode):
        try:
            os.unlink(path)
        except OSError as exc:
            raise IPCError(f"cannot remove stale socket {path}: {exc}") from exc


def prepare_listener(
    path: str | os.PathLike[str], *, backlog: int = DEFAULT_BACKLOG
) -> socket.socket:
    """Create a bound, listening AF_UNIX socket at ``path``.

    Replaces a stale socket file; refuses any non-socket file or symlink so
    an attacker-controlled path is never unlinked.
    """
    path = Path(path)
    parent = path.parent
    created_parent = not parent.exists()
    try:
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if created_parent:
            os.chmod(parent, 0o700)
    except OSError as exc:
        raise IPCError(f"cannot create socket directory {parent}: {exc}") from exc

    try:
        st = os.lstat(path)
    except FileNotFoundError:
        st = None
    except OSError as exc:
        raise IPCError(f"cannot stat socket path {path}: {exc}") from exc
    if st is not None:
        if stat.S_ISSOCK(st.st_mode):
            try:
                os.unlink(path)
            except OSError as exc:
                raise IPCError(f"cannot remove stale socket {path}: {exc}") from exc
        else:
            raise IPCError(f"refusing to replace non-socket path: {path}")

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind(str(path))
        os.chmod(path, 0o600)
        sock.listen(backlog)
    except OSError as exc:
        sock.close()
        raise IPCError(f"cannot bind security socket {path}: {exc}") from exc
    return sock


def connect(
    path: str | os.PathLike[str], *, timeout: float | None = DEFAULT_CONNECT_TIMEOUT
) -> socket.socket:
    """Connect to the PDP socket at ``path`` (fail closed)."""
    path = Path(path)
    if not os.path.lexists(path):
        raise IPCError(f"security socket not found: {path}")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if timeout is not None:
        sock.settimeout(timeout)
    try:
        sock.connect(str(path))
    except OSError as exc:
        sock.close()
        raise IPCError(f"cannot connect to security socket {path}: {exc}") from exc
    return sock


def peer_credentials(sock: socket.socket) -> PeerCredentials | None:
    """Return the peer's (pid, uid, gid) when the platform exposes them.

    ``SO_PEERCRED`` is Linux-only; on other platforms this returns ``None``
    and callers must rely on socket-file permissions instead.
    """
    level = getattr(socket, "SO_PEERCRED", None)
    if level is None:
        return None
    try:
        raw = sock.getsockopt(socket.SOL_SOCKET, level, _PEERCRED_STRUCT.size)
    except OSError:
        return None
    pid, uid, gid = _PEERCRED_STRUCT.unpack(raw)
    return PeerCredentials(pid=pid, uid=uid, gid=gid)


__all__ = [
    "SOCKET_ENV",
    "RUN_DIR",
    "SOCKET_NAME",
    "DEFAULT_BACKLOG",
    "DEFAULT_CONNECT_TIMEOUT",
    "PeerCredentials",
    "resolve_socket_path",
    "prepare_listener",
    "connect",
    "peer_credentials",
    "unlink_socket",
]
