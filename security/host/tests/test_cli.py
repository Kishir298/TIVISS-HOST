"""CLI engine construction, error paths, and a subprocess smoke test."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from tiviss_security_protocol import Decision

from tiviss_security_host import PolicyError
from tiviss_security_host.cli import build_engine, build_parser, main

from .test_engine import request
from .test_server import _decide


def test_build_engine_inline_rules():
    args = build_parser().parse_args(
        ["--allow", "memory.*", "--deny", "memory.secret"]
    )
    engine = build_engine(args)
    assert engine.decide(request(action="memory.store")) is Decision.ALLOW
    assert engine.decide(request(action="memory.secret")) is Decision.DENY
    assert engine.decide(request(action="tools.run")) is Decision.DENY


def test_build_engine_policy_file_plus_inline(tmp_path: Path):
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps({"allow": ["memory.*"], "deny": ["memory.secret"]}),
        encoding="utf-8",
    )
    args = build_parser().parse_args(
        ["--policy", str(policy), "--deny", "handover.start"]
    )
    engine = build_engine(args)
    assert engine.decide(request(action="memory.store")) is Decision.ALLOW
    assert engine.decide(request(action="memory.secret")) is Decision.DENY
    assert engine.decide(request(action="handover.start")) is Decision.DENY


def test_build_engine_rejects_unknown_policy_keys(tmp_path: Path):
    policy = tmp_path / "bad.json"
    policy.write_text('{"allow": ["memory.*"], "sudo": true}', encoding="utf-8")
    args = build_parser().parse_args(["--policy", str(policy)])
    with pytest.raises(PolicyError, match="unknown policy keys"):
        build_engine(args)


def test_build_engine_rejects_malformed_json(tmp_path: Path):
    policy = tmp_path / "bad.json"
    policy.write_text('{"allow": [', encoding="utf-8")
    args = build_parser().parse_args(["--policy", str(policy)])
    with pytest.raises(json.JSONDecodeError):
        build_engine(args)


def test_main_missing_policy_file_returns_2(tmp_path: Path, capsys):
    args = ["--policy", str(tmp_path / "nope.json"), "--quiet"]
    assert main(args) == 2
    assert "tiviss-security-pdp:" in capsys.readouterr().err


def test_main_bind_error_returns_1(tmp_path: Path, capsys):
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    assert main(["--socket", str(blocker / "pdp.sock"), "--quiet"]) == 1
    assert "tiviss-security-pdp:" in capsys.readouterr().err


def test_cli_subprocess_smoke(sock_dir: Path):
    """Start the real CLI, decide over the socket, then terminate it."""
    host_root = Path(__file__).resolve().parents[1]
    security_root = host_root.parent
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [
            str(host_root),
            str(security_root / "ipc"),
            str(security_root / "protocol"),
        ]
    )
    sock = sock_dir / "cli.sock"
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "tiviss_security_host",
            "--socket",
            str(sock),
            "--allow",
            "memory.*",
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        response = None
        deadline = time.time() + 10.0
        while time.time() < deadline:
            if proc.poll() is not None:
                out, err = proc.communicate(timeout=2)
                pytest.fail(
                    f"CLI exited early rc={proc.returncode} out={out!r} err={err!r}"
                )
            if sock.exists():
                try:
                    response = _decide(str(sock))
                    break
                except (OSError, Exception):  # noqa: BLE001 — retry until ready
                    time.sleep(0.1)
            else:
                time.sleep(0.1)
        assert response is not None, "CLI never became ready"
        assert response["payload"]["decision"] == "allow"
        assert response["type"] == "pdp.decide"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
