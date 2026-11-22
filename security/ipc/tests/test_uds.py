"""Socket path resolution and listener hardening."""

from __future__ import annotations

import os
import stat
import tempfile
import threading
from pathlib import Path

import pytest

from tiviss_security_ipc import (
    IPCError,
    connect,
    peer_credentials,
    prepare_listener,
    resolve_socket_path,
    uds,
    unlink_socket,
)


def _neutral_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv(uds.SOCKET_ENV, raising=False)
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    monkeypatch.setattr(uds, "RUN_DIR", tmp_path / "no-such-run")


def test_explicit_path_wins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(uds.SOCKET_ENV, str(tmp_path / "env.sock"))
    explicit = tmp_path / "explicit.sock"
    assert resolve_socket_path(explicit) == explicit


def test_env_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    env_path = tmp_path / "from-env.sock"
    monkeypatch.setenv(uds.SOCKET_ENV, str(env_path))
    assert resolve_socket_path() == env_path


def test_blank_env_is_ignored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _neutral_env(monkeypatch, tmp_path)
    monkeypatch.setenv(uds.SOCKET_ENV, "   ")
    expected = Path(tempfile.gettempdir()) / "tiviss" / "security.sock"
    assert resolve_socket_path() == expected


def test_run_dir_used_when_writable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    run_dir = tmp_path / "run-tiviss"
    run_dir.mkdir(mode=0o700)
    monkeypatch.delenv(uds.SOCKET_ENV, raising=False)
    monkeypatch.setattr(uds, "RUN_DIR", run_dir)
    assert resolve_socket_path() == run_dir / "security.sock"


def test_xdg_runtime_dir_used(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _neutral_env(monkeypatch, tmp_path)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    assert resolve_socket_path() == tmp_path / "tiviss" / "security.sock"


def test_default_falls_back_to_temp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _neutral_env(monkeypatch, tmp_path)
    expected = Path(tempfile.gettempdir()) / "tiviss" / "security.sock"
    assert resolve_socket_path() == expected


def test_prepare_listener_creates_private_socket(sock_dir: Path):
    path = sock_dir / "run" / "security.sock"
    listener = prepare_listener(path)
    try:
        st = os.lstat(path)
        assert stat.S_ISSOCK(st.st_mode)
        assert stat.S_IMODE(st.st_mode) == 0o600
        parent_mode = stat.S_IMODE(os.lstat(path.parent).st_mode)
        assert parent_mode == 0o700
    finally:
        listener.close()
        unlink_socket(path)
    assert not path.exists()


def test_prepare_listener_replaces_stale_socket(sock_dir: Path):
    path = sock_dir / "s.sock"
    first = prepare_listener(path)
    first.close()  # socket file remains behind (stale)
    assert path.exists()
    second = prepare_listener(path)
    try:
        assert stat.S_ISSOCK(os.lstat(path).st_mode)
    finally:
        second.close()
        unlink_socket(path)


def test_prepare_listener_refuses_regular_file(tmp_path: Path):
    path = tmp_path / "s.sock"
    path.write_text("not a socket")
    with pytest.raises(IPCError, match="non-socket"):
        prepare_listener(path)
    assert path.read_text() == "not a socket"  # untouched


def test_prepare_listener_refuses_symlink(tmp_path: Path):
    target = tmp_path / "target.sock"
    target.write_text("data")
    path = tmp_path / "link.sock"
    path.symlink_to(target)
    with pytest.raises(IPCError, match="non-socket"):
        prepare_listener(path)
    assert target.exists()


def test_connect_missing_socket(tmp_path: Path):
    with pytest.raises(IPCError, match="not found"):
        connect(tmp_path / "missing.sock")


def test_connect_refuses_regular_file(tmp_path: Path):
    path = tmp_path / "s.sock"
    path.write_text("data")
    with pytest.raises(IPCError, match="cannot connect"):
        connect(path)


def test_connect_and_peer_credentials(sock_dir: Path):
    path = sock_dir / "s.sock"
    listener = prepare_listener(path)
    accepted: dict[str, object] = {}

    def accept() -> None:
        conn, _ = listener.accept()
        try:
            accepted["creds"] = peer_credentials(conn)
        finally:
            conn.close()

    thread = threading.Thread(target=accept)
    thread.start()
    client = connect(path, timeout=2.0)
    client_creds = peer_credentials(client)
    client.close()
    thread.join(timeout=2)
    listener.close()
    unlink_socket(path)

    if client_creds is None:
        # Platform without SO_PEERCRED (e.g. macOS) — both sides None.
        assert accepted.get("creds") is None
    else:
        assert client_creds.uid == os.getuid()
        server_creds = accepted.get("creds")
        assert isinstance(server_creds, type(client_creds))
        assert server_creds.uid == os.getuid()


def test_unlink_socket_missing_is_noop(tmp_path: Path):
    unlink_socket(tmp_path / "absent.sock")  # must not raise


def test_unlink_socket_leaves_regular_file_alone(tmp_path: Path):
    path = tmp_path / "s.sock"
    path.write_text("keep me")
    unlink_socket(path)
    assert path.read_text() == "keep me"
