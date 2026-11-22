"""Security facade: embedded or daemon-backed policy decisions.

Runtime model C ("library + local PDP daemon"):

- ``security.mode = "embedded"`` — :class:`EmbeddedPDP` evaluates rules
  in-process with ``tiviss-security-host``'s :class:`PolicyEngine`.
- ``security.mode = "daemon"``  — :class:`DaemonPDP` forwards questions to
  the local PDP daemon over its Unix socket via ``tiviss-security-client``.

Both implementations are fail closed: an unreachable daemon raises
:class:`SecurityUnavailableError`, and :meth:`PDP.allowed` turns that into
``False`` instead of a grant.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from tiviss_security_client import PDPError, SecurityClient
from tiviss_security_host import PolicyEngine
from tiviss_security_ipc import IPCError
from tiviss_security_protocol import (
    DecisionRequest,
    DecisionResponse,
    ProtocolError,
)

from .errors import (
    SecurityConfigurationError,
    SecurityError,
    SecurityUnavailableError,
)

if TYPE_CHECKING:
    from ..configuration import TIVISSConfig

__all__ = [
    "PDP",
    "EmbeddedPDP",
    "DaemonPDP",
    "make_request",
    "create_pdp",
]


def make_request(
    subject: str,
    action: str,
    resource: str,
    *,
    context: dict[str, Any] | None = None,
    request_id: str | None = None,
) -> DecisionRequest:
    """Build a protocol decision request (the one wire-level question)."""
    kwargs: dict[str, Any] = {"context": dict(context or {})}
    if request_id is not None:
        kwargs["request_id"] = request_id
    return DecisionRequest(subject=subject, action=action, resource=resource, **kwargs)


class PDP(ABC):
    """What every embedder sees: one question, one answer."""

    @abstractmethod
    def decide(self, request: DecisionRequest) -> DecisionResponse:
        """Answer ``request``; raises ``SecurityUnavailableError`` when the
        daemon-backed PDP cannot be reached."""

    def allowed(
        self,
        subject: str,
        action: str,
        resource: str,
        *,
        context: dict[str, Any] | None = None,
    ) -> bool:
        """Boolean convenience: ``False`` on deny **and** on unavailability."""
        try:
            response = self.decide(
                make_request(subject, action, resource, context=context)
            )
        except SecurityUnavailableError:
            return False
        return response.allowed


class EmbeddedPDP(PDP):
    """In-process policy engine (``security.mode = "embedded"``)."""

    def __init__(self, engine: PolicyEngine) -> None:
        self.engine = engine

    def decide(self, request: DecisionRequest) -> DecisionResponse:
        if not isinstance(request, DecisionRequest):
            raise TypeError(
                f"request must be DecisionRequest, got {type(request).__name__}"
            )
        decision, reason = self.engine.decide_detailed(request)
        return DecisionResponse(
            decision=decision,
            request_id=request.request_id,
            reason=reason,
        )


class DaemonPDP(PDP):
    """Forward questions to the local PDP daemon (``security.mode = "daemon"``)."""

    def __init__(self, client: SecurityClient) -> None:
        self.client = client

    def decide(self, request: DecisionRequest) -> DecisionResponse:
        if not isinstance(request, DecisionRequest):
            raise TypeError(
                f"request must be DecisionRequest, got {type(request).__name__}"
            )
        try:
            return self.client.decide(request)
        except IPCError as exc:
            raise SecurityUnavailableError(
                f"security daemon unavailable at {self.client.address}: {exc}"
            ) from exc
        except PDPError as exc:
            raise SecurityError(
                f"security daemon rejected the request: {exc}"
            ) from exc
        except ProtocolError as exc:
            raise SecurityError(
                f"invalid response from security daemon: {exc}"
            ) from exc


def create_pdp(config: TIVISSConfig | None = None) -> PDP:
    """Build the PDP described by ``config.security`` (fail closed)."""
    if config is None:
        from ..configuration import TIVISSConfig as _TIVISSConfig

        config = _TIVISSConfig.defaults()
    mode = config.security.mode
    if mode == "embedded":
        engine = PolicyEngine.from_permission_lists(
            allow=config.permissions.allow,
            deny=config.permissions.deny,
        )
        return EmbeddedPDP(engine)
    if mode == "daemon":
        client = SecurityClient(
            config.security.socket_path or None,
            timeout=config.security.request_timeout_s,
        )
        return DaemonPDP(client)
    raise SecurityConfigurationError(
        f"security.mode must be 'embedded' or 'daemon', got {mode!r}"
    )
