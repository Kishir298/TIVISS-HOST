"""SecurityClient behaviour against a real or fake PDP daemon."""

from __future__ import annotations

from pathlib import Path

import pytest
from tiviss_security_host import PDPServer, PolicyEngine
from tiviss_security_ipc import IPCError
from tiviss_security_protocol import (
    PROTOCOL_VERSION,
    Decision,
    DecisionRequest,
    envelope,
)

from tiviss_security_client import PDPError, SecurityClient

from .fake import fake_server


def decide_request(action: str = "memory.store") -> DecisionRequest:
    return DecisionRequest(
        subject="alice", action=action, resource="doc/1"
    )


def test_decide_allow_and_deny(sock_dir: Path):
    path = str(sock_dir / "pdp.sock")
    server = PDPServer(
        PolicyEngine.from_permission_lists(
            allow=["memory.*"], deny=["memory.secret"]
        ),
        socket_path=path,
        request_timeout_s=2.0,
    )
    server.start()
    try:
        client = SecurityClient(path, timeout=2.0)
        allow = client.decide(decide_request())
        assert allow.decision is Decision.ALLOW
        assert allow.request_id
        assert "explicit allow" in allow.reason

        deny = client.decide(decide_request(action="memory.secret"))
        assert deny.decision is Decision.DENY

        unknown = client.decide(decide_request(action="tools.run"))
        assert unknown.decision is Decision.DENY
    finally:
        server.stop()


def test_health_and_version(sock_dir: Path):
    path = str(sock_dir / "pdp.sock")
    server = PDPServer(PolicyEngine(), socket_path=path)
    server.start()
    try:
        client = SecurityClient(path, timeout=2.0)
        health = client.health()
        assert health["status"] == "ok"
        assert health["server"] == "tiviss-security-host"
        version = client.version()
        assert version["protocol_version"] == PROTOCOL_VERSION
        assert version["server"] == "tiviss-security-host"
    finally:
        server.stop()


def test_missing_socket_raises_ipc_error(tmp_path: Path):
    client = SecurityClient(str(tmp_path / "absent.sock"), timeout=1.0)
    with pytest.raises(IPCError, match="not found"):
        client.health()


def test_stopped_server_raises_ipc_error(sock_dir: Path):
    path = str(sock_dir / "pdp.sock")
    server = PDPServer(PolicyEngine(), socket_path=path)
    server.start()
    server.stop()
    client = SecurityClient(path, timeout=1.0)
    with pytest.raises(IPCError, match="not found"):
        client.version()


def test_timeout_must_be_positive():
    with pytest.raises(ValueError, match="timeout"):
        SecurityClient(timeout=0)


def test_rejects_non_decision_request(sock_dir: Path):
    with pytest.raises(TypeError, match="DecisionRequest"):
        SecurityClient(str(sock_dir / "pdp.sock")).decide({"subject": "a"})


def test_decide_raises_pdp_error_on_error_envelope(sock_dir: Path):
    path = str(sock_dir / "fake.sock")

    def handler(request: dict) -> dict:
        return envelope(
            "pdp.error",
            {"code": "bad_request", "message": "nope"},
            msg_id=request["id"],
        )

    with fake_server(path, handler):
        client = SecurityClient(path, timeout=2.0)
        with pytest.raises(PDPError) as excinfo:
            client.decide(decide_request())
        assert excinfo.value.code == "bad_request"
        assert excinfo.value.message == "nope"


def test_decide_raises_on_unexpected_response_type(sock_dir: Path):
    path = str(sock_dir / "fake.sock")

    def handler(request: dict) -> dict:
        return envelope("pdp.health", {"status": "ok"}, msg_id=request["id"])

    with fake_server(path, handler):
        client = SecurityClient(path, timeout=2.0)
        with pytest.raises(PDPError, match="unexpected_response"):
            client.decide(decide_request())


def test_env_socket_resolution(sock_dir: Path, monkeypatch: pytest.MonkeyPatch):
    path = str(sock_dir / "env.sock")
    monkeypatch.setenv("TIVISS_SECURITY_SOCKET", path)
    server = PDPServer(PolicyEngine(), socket_path=path)
    server.start()
    try:
        client = SecurityClient(timeout=2.0)  # no explicit path
        assert client.health()["status"] == "ok"
    finally:
        server.stop()
