"""Full daemon loop through the security facade (mode = "daemon")."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest
from tiviss_security_host import PDPServer, PolicyEngine

from tiviss.configuration import TIVISSConfig
from tiviss.security import (
    DaemonPDP,
    SecurityUnavailableError,
    create_pdp,
    make_request,
)


@pytest.fixture()
def sock_dir() -> Path:
    path = Path(tempfile.mkdtemp(prefix="tsec-", dir="/tmp"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture()
def daemon(sock_dir: Path):
    server = PDPServer(
        PolicyEngine.from_permission_lists(allow=["memory.*"]),
        socket_path=str(sock_dir / "pdp.sock"),
        request_timeout_s=2.0,
    )
    server.start()
    try:
        yield server
    finally:
        server.stop()


def test_daemon_mode_full_loop(daemon: PDPServer, sock_dir: Path):
    config = TIVISSConfig.load(
        {
            "security": {
                "mode": "daemon",
                "socket_path": str(sock_dir / "pdp.sock"),
                "request_timeout_s": 2.0,
            }
        }
    )
    pdp = create_pdp(config)
    assert isinstance(pdp, DaemonPDP)

    # Daemon-side rules decide — config.permissions are NOT consulted.
    assert pdp.allowed("alice", "memory.store", "doc") is True
    assert pdp.allowed("alice", "tools.execute", "bin") is False

    response = pdp.decide(make_request("alice", "memory.load", "doc"))
    assert response.decision.value == "allow"
    assert response.request_id

    health = pdp.client.health()
    assert health["status"] == "ok"
    assert health["decisions"]["total"] == 3


def test_daemon_mode_ignores_embedded_permissions(daemon: PDPServer, sock_dir: Path):
    config = TIVISSConfig.load(
        {
            "permissions": {"allow": ["tools.*"]},  # embedded-style rule
            "security": {
                "mode": "daemon",
                "socket_path": str(sock_dir / "pdp.sock"),
            },
        }
    )
    pdp = create_pdp(config)
    # Daemon allows memory.*, not tools.* — the daemon's engine is authoritative.
    assert pdp.allowed("alice", "memory.store", "doc") is True
    assert pdp.allowed("alice", "tools.execute", "bin") is False


def test_daemon_mode_socket_from_env(sock_dir: Path, monkeypatch: pytest.MonkeyPatch):
    path = str(sock_dir / "env.sock")
    monkeypatch.setenv("TIVISS_SECURITY_SOCKET", path)
    server = PDPServer(PolicyEngine(), socket_path=path, request_timeout_s=2.0)
    server.start()
    try:
        config = TIVISSConfig.load({"security": {"mode": "daemon"}})
        pdp = create_pdp(config)
        assert pdp.allowed("alice", "anything", "x") is False  # engine default deny
        health = pdp.client.health()
        assert health["status"] == "ok"
    finally:
        server.stop()


def test_daemon_mode_after_stop_fails_closed(daemon: PDPServer, sock_dir: Path):
    config = TIVISSConfig.load(
        {
            "security": {
                "mode": "daemon",
                "socket_path": str(sock_dir / "pdp.sock"),
            }
        }
    )
    pdp = create_pdp(config)
    assert pdp.allowed("alice", "memory.store", "doc") is True
    daemon.stop()
    with pytest.raises(SecurityUnavailableError):
        pdp.decide(make_request("a", "b", "c"))
    assert pdp.allowed("alice", "memory.store", "doc") is False
