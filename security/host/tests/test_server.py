"""PDPServer end-to-end behaviour over a real Unix socket."""

from __future__ import annotations

import time

import pytest
from tiviss_security_ipc import Channel, IPCError, request_once
from tiviss_security_protocol import (
    PROTOCOL_VERSION,
    TYPE_DECIDE,
    TYPE_HEALTH,
    TYPE_VERSION,
    Decision,
    DecisionRequest,
    envelope,
)

from tiviss_security_host import PDPServer, PolicyEngine

from .test_engine import request


@pytest.fixture()
def server(sock_dir):
    srv = PDPServer(
        PolicyEngine.from_permission_lists(allow=["memory.*"]),
        socket_path=str(sock_dir / "pdp.sock"),
        request_timeout_s=2.0,
    )
    srv.start()
    try:
        yield srv
    finally:
        srv.stop()


def _decide(sock, subject="alice", action="memory.store", resource="doc"):
    payload = DecisionRequest(
        subject=subject, action=action, resource=resource
    ).to_dict()
    return request_once(sock, envelope(TYPE_DECIDE, payload), timeout=2.0)


def test_decide_allow(server, sock_dir):
    from tiviss_security_protocol import DecisionResponse

    response = _decide(str(sock_dir / "pdp.sock"))
    assert response["type"] == TYPE_DECIDE
    parsed = DecisionResponse.from_dict(response["payload"])
    assert parsed.decision is Decision.ALLOW
    assert parsed.request_id
    assert "explicit allow" in parsed.reason


def test_decide_deny(server, sock_dir):
    from tiviss_security_protocol import DecisionResponse

    response = _decide(str(sock_dir / "pdp.sock"), action="tools.execute")
    parsed = DecisionResponse.from_dict(response["payload"])
    assert parsed.decision is Decision.DENY
    assert "default deny" in parsed.reason


def test_health(server, sock_dir):
    sock = str(sock_dir / "pdp.sock")
    _decide(sock)
    response = request_once(sock, envelope(TYPE_HEALTH, {}), timeout=2.0)
    assert response["type"] == TYPE_HEALTH
    payload = response["payload"]
    assert payload["status"] == "ok"
    assert payload["server"] == "tiviss-security-host"
    assert payload["decisions"]["total"] == 1
    assert payload["decisions"]["allow"] == 1
    assert payload["engine_default"] == "deny"
    assert payload["requests_total"] >= 2


def test_version(server, sock_dir):
    response = request_once(
        str(sock_dir / "pdp.sock"), envelope(TYPE_VERSION, {}), timeout=2.0
    )
    assert response["type"] == TYPE_VERSION
    payload = response["payload"]
    assert payload["protocol_version"] == PROTOCOL_VERSION
    assert payload["server"] == "tiviss-security-host"
    assert payload["server_version"] == "0.1.0"


def test_bad_request_answered_with_error(sock_dir):
    srv = PDPServer(PolicyEngine(), socket_path=str(sock_dir / "pdp.sock"))
    srv.start()
    try:
        response = request_once(
            str(sock_dir / "pdp.sock"),
            envelope(TYPE_DECIDE, {"subject": 42}),
            timeout=2.0,
        )
        assert response["type"] == "pdp.error"
        assert response["payload"]["code"] == "bad_request"
    finally:
        srv.stop()


def test_unknown_type_answered_with_error(server, sock_dir):
    response = request_once(
        str(sock_dir / "pdp.sock"), envelope("pdp.shutdown", {}), timeout=2.0
    )
    assert response["type"] == "pdp.error"
    assert response["payload"]["code"] == "unknown_type"


def test_wrong_protocol_version_fails_closed(sock_dir):
    srv = PDPServer(PolicyEngine(), socket_path=str(sock_dir / "pdp.sock"))
    srv.start()
    try:
        message = envelope(TYPE_HEALTH, {})
        message["v"] = PROTOCOL_VERSION + 99
        # Server sees an invalid envelope: responds with pdp.error (bad_envelope).
        response = request_once(
            str(sock_dir / "pdp.sock"), message, timeout=2.0
        )
        assert response["type"] == "pdp.error"
        assert response["payload"]["code"] == "bad_envelope"
    finally:
        srv.stop()


def test_malformed_frame_drops_connection(sock_dir):
    import socket
    import struct

    srv = PDPServer(PolicyEngine(), socket_path=str(sock_dir / "pdp.sock"))
    srv.start()
    try:
        raw = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        raw.settimeout(2.0)
        raw.connect(str(sock_dir / "pdp.sock"))
        raw.sendall(struct.pack(">I", 10_000_000))
        # Server must drop us: next read returns EOF (b"").
        assert raw.recv(4) == b""
        raw.close()
    finally:
        srv.stop()


def test_persistent_connection_serves_multiple_requests(server, sock_dir):
    with Channel.connect(str(sock_dir / "pdp.sock"), timeout=2.0) as channel:
        first = channel.request(
            envelope(TYPE_DECIDE, request(action="memory.store").to_dict()),
            timeout=2.0,
        )
        second = channel.request(envelope(TYPE_VERSION, {}), timeout=2.0)
        third = channel.request(envelope(TYPE_HEALTH, {}), timeout=2.0)
    assert first["type"] == TYPE_DECIDE
    assert second["type"] == TYPE_VERSION
    assert third["type"] == TYPE_HEALTH


def test_stop_removes_socket(server, sock_dir):
    path = sock_dir / "pdp.sock"
    assert path.exists()
    server.stop()
    assert not path.exists()
    with pytest.raises(IPCError, match="not found"):
        request_once(str(path), envelope(TYPE_HEALTH, {}), timeout=1.0)


def test_start_twice_raises(server):
    with pytest.raises(RuntimeError, match="already started"):
        server.start()


def test_concurrent_decisions(sock_dir):
    import threading

    srv = PDPServer(
        PolicyEngine.from_permission_lists(allow=["memory.*"]),
        socket_path=str(sock_dir / "pdp.sock"),
        request_timeout_s=2.0,
    )
    srv.start()
    results: list[str] = []

    def worker() -> None:
        response = _decide(str(sock_dir / "pdp.sock"))
        results.append(response["payload"]["decision"])

    try:
        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        assert results == ["allow"] * 8
        snapshot = srv.engine.stats.snapshot()
        assert snapshot["total"] == 8
        assert snapshot["allow"] == 8
    finally:
        srv.stop()


def test_server_context_manager(sock_dir):
    path = str(sock_dir / "pdp.sock")
    with PDPServer(PolicyEngine(), socket_path=path) as srv:
        assert srv.running
        assert (srv.address).exists()
    time.sleep(0.05)
    assert not srv.running
