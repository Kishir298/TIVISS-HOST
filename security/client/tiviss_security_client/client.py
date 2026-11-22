"""Client for the local T.I.V.I.S.S. PDP daemon."""

from __future__ import annotations

from tiviss_security_ipc import Channel, resolve_socket_path
from tiviss_security_protocol import (
    TYPE_DECIDE,
    TYPE_HEALTH,
    TYPE_VERSION,
    DecisionRequest,
    DecisionResponse,
    envelope,
    validate_envelope,
)

__version__ = "0.1.0"

_ERROR_TYPE = "pdp.error"


class PDPError(Exception):
    """The daemon answered with a ``pdp.error`` envelope."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


class SecurityClient:
    """Ask the local PDP daemon for decisions (one connection per call)."""

    def __init__(
        self, socket_path: str | None = None, *, timeout: float = 5.0
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be > 0")
        self.address = resolve_socket_path(socket_path)
        self.timeout = timeout

    def _call(self, msg_type: str, payload: dict) -> tuple[str, dict]:
        with Channel.connect(self.address, timeout=self.timeout) as channel:
            response = channel.request(
                envelope(msg_type, payload), timeout=self.timeout
            )
        _msg_id, response_type, response_payload = validate_envelope(response)
        if response_type == _ERROR_TYPE:
            raise PDPError(
                str(response_payload.get("code", "error")),
                str(response_payload.get("message", "")),
            )
        if response_type != msg_type:
            raise PDPError(
                "unexpected_response",
                f"expected {msg_type!r}, got {response_type!r}",
            )
        return response_type, response_payload

    def decide(self, request: DecisionRequest) -> DecisionResponse:
        """Send ``request`` to the daemon and return its decision."""
        if not isinstance(request, DecisionRequest):
            raise TypeError(
                f"request must be DecisionRequest, got {type(request).__name__}"
            )
        _msg_type, payload = self._call(TYPE_DECIDE, request.to_dict())
        return DecisionResponse.from_dict(payload)

    def health(self) -> dict:
        """Return the daemon health payload (status, counters, uptime)."""
        _msg_type, payload = self._call(TYPE_HEALTH, {})
        return payload

    def version(self) -> dict:
        """Return the daemon version payload."""
        _msg_type, payload = self._call(TYPE_VERSION, {})
        return payload


__all__ = ["PDPError", "SecurityClient", "__version__"]
