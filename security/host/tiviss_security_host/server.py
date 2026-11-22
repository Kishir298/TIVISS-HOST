"""Local PDP daemon: serves protocol decisions over a Unix domain socket.

Wire behaviour (fail closed):
  - ``pdp.decide``  -> :class:`DecisionResponse` payload (engine decides)
  - ``pdp.health``  -> uptime + request/decision counters
  - ``pdp.version`` -> protocol + server versions
  - unknown type / bad envelope / bad request -> ``pdp.error`` payload
  - malformed frame  -> connection is dropped
"""

from __future__ import annotations

import contextlib
import socket
import threading
import time
from pathlib import Path
from typing import Any

from tiviss_security_ipc import (
    IPCError,
    prepare_listener,
    resolve_socket_path,
    unlink_socket,
)
from tiviss_security_protocol import (
    PROTOCOL_NAME,
    PROTOCOL_VERSION,
    TYPE_DECIDE,
    TYPE_HEALTH,
    TYPE_VERSION,
    DecisionRequest,
    DecisionResponse,
    FrameError,
    SchemaError,
    envelope,
    read_frame,
    send_frame,
    validate_envelope,
)

from .engine import PolicyEngine

__version__ = "0.1.0"

TYPE_ERROR = "pdp.error"
DEFAULT_REQUEST_TIMEOUT_S = 10.0
_ACCEPT_POLL_S = 0.25


class PDPServer:
    """Threaded Unix-socket PDP server."""

    def __init__(
        self,
        engine: PolicyEngine | None = None,
        *,
        socket_path: str | None = None,
        request_timeout_s: float = DEFAULT_REQUEST_TIMEOUT_S,
        backlog: int = 64,
    ) -> None:
        if request_timeout_s <= 0:
            raise ValueError("request_timeout_s must be > 0")
        self.engine = engine if engine is not None else PolicyEngine()
        self.address: Path = resolve_socket_path(socket_path)
        self.request_timeout_s = request_timeout_s
        self.backlog = backlog
        self._stop = threading.Event()
        self._listener: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._conn_threads: set[threading.Thread] = set()
        self._conn_lock = threading.Lock()
        self._requests_total = 0
        self._requests_lock = threading.Lock()
        self._started_at = 0.0
        self._owns_socket = False

    @property
    def running(self) -> bool:
        thread = self._accept_thread
        return thread is not None and thread.is_alive()

    @property
    def requests_total(self) -> int:
        with self._requests_lock:
            return self._requests_total

    def start(self) -> None:
        """Bind, listen, and serve in a background thread."""
        if self.running:
            raise RuntimeError("PDPServer already started")
        self._stop.clear()
        self._listener = prepare_listener(self.address, backlog=self.backlog)
        self._listener.settimeout(_ACCEPT_POLL_S)
        self._owns_socket = True
        self._started_at = time.time()
        with self._requests_lock:
            self._requests_total = 0
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="tiviss-pdp-accept", daemon=True
        )
        self._accept_thread.start()

    def serve_forever(self) -> None:
        """Start and block until :meth:`stop` is called (from another thread)."""
        self.start()
        try:
            while not self._stop.wait(_ACCEPT_POLL_S):
                pass
        finally:
            self.stop()

    def stop(self) -> None:
        """Stop serving, close connections, and remove the socket file."""
        self._stop.set()
        listener = self._listener
        if listener is not None:
            with contextlib.suppress(OSError):
                listener.close()
            self._listener = None
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=2.0)
            self._accept_thread = None
        with self._conn_lock:
            conn_threads = tuple(self._conn_threads)
        for thread in conn_threads:
            thread.join(timeout=1.0)
        with self._conn_lock:
            self._conn_threads.clear()
        if self._owns_socket:
            with contextlib.suppress(IPCError):
                unlink_socket(self.address)
            self._owns_socket = False

    def __enter__(self) -> PDPServer:
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    # ------------------------------------------------------------------ #

    def _accept_loop(self) -> None:
        assert self._listener is not None
        while not self._stop.is_set():
            try:
                conn, _addr = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            thread = threading.Thread(
                target=self._serve_connection,
                args=(conn,),
                name="tiviss-pdp-conn",
                daemon=True,
            )
            with self._conn_lock:
                self._conn_threads.add(thread)
            thread.start()

    def _serve_connection(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(self.request_timeout_s)
            while not self._stop.is_set():
                try:
                    message = read_frame(conn.recv)
                except OSError:
                    break  # includes idle-timeout and closed connections
                except FrameError:
                    break  # malformed input: drop the connection (fail closed)
                try:
                    response = self._dispatch(message)
                    send_frame(conn.sendall, response)
                except (FrameError, OSError):
                    break
        finally:
            with contextlib.suppress(OSError):
                conn.close()
            with self._conn_lock:
                self._conn_threads.discard(threading.current_thread())

    def _count_request(self) -> None:
        with self._requests_lock:
            self._requests_total += 1

    def _dispatch(self, message: dict[str, Any]) -> dict[str, Any]:
        self._count_request()
        try:
            msg_id, msg_type, payload = validate_envelope(message)
        except FrameError as exc:
            return envelope(
                TYPE_ERROR, {"code": "bad_envelope", "message": str(exc)}
            )
        if msg_type == TYPE_DECIDE:
            return self._dispatch_decide(msg_id, payload)
        if msg_type == TYPE_HEALTH:
            return envelope(TYPE_HEALTH, self._health_payload(), msg_id=msg_id)
        if msg_type == TYPE_VERSION:
            return envelope(
                TYPE_VERSION,
                {
                    "name": PROTOCOL_NAME,
                    "protocol_version": PROTOCOL_VERSION,
                    "server": "tiviss-security-host",
                    "server_version": __version__,
                },
                msg_id=msg_id,
            )
        return envelope(
            TYPE_ERROR,
            {"code": "unknown_type", "message": f"unsupported type: {msg_type!r}"},
            msg_id=msg_id,
        )

    def _dispatch_decide(
        self, msg_id: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        try:
            request = DecisionRequest.from_dict(payload)
        except SchemaError as exc:
            return envelope(
                TYPE_ERROR,
                {"code": "bad_request", "message": str(exc)},
                msg_id=msg_id,
            )
        decision, reason = self.engine.decide_detailed(request)
        response = DecisionResponse(
            decision=decision,
            request_id=request.request_id,
            reason=reason,
        )
        return envelope(TYPE_DECIDE, response.to_dict(), msg_id=msg_id)

    def _health_payload(self) -> dict[str, Any]:
        uptime = time.time() - self._started_at if self._started_at else 0.0
        return {
            "status": "ok",
            "server": "tiviss-security-host",
            "server_version": __version__,
            "uptime_s": round(uptime, 3),
            "requests_total": self.requests_total,
            "decisions": self.engine.stats.snapshot(),
            "engine_default": str(self.engine.default),
        }


__all__ = ["PDPServer", "TYPE_ERROR", "__version__"]
