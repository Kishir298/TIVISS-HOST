"""Security facade: config wiring, embedded mode, fail-closed daemon mode."""

from __future__ import annotations

import pytest

from tiviss.configuration import ConfigValidationError, TIVISSConfig
from tiviss.security import (
    PDP,
    DaemonPDP,
    EmbeddedPDP,
    SecurityConfigurationError,
    SecurityUnavailableError,
    create_pdp,
    make_request,
)


def test_config_security_defaults():
    config = TIVISSConfig.defaults()
    assert config.security.mode == "embedded"
    assert config.security.socket_path == ""
    assert config.security.request_timeout_s == 5.0


def test_config_load_security_mapping():
    config = TIVISSConfig.load(
        {
            "security": {
                "mode": "DAEMON",
                "socket_path": "/tmp/pdp.sock",
                "request_timeout_s": 2.5,
            }
        }
    )
    assert config.security.mode == "daemon"  # normalised
    assert config.security.socket_path == "/tmp/pdp.sock"
    assert config.security.request_timeout_s == 2.5


def test_config_rejects_unknown_mode():
    with pytest.raises(ConfigValidationError, match="security.mode"):
        TIVISSConfig.load({"security": {"mode": "banana"}})


def test_config_rejects_non_positive_timeout():
    with pytest.raises(ConfigValidationError, match="request_timeout_s"):
        TIVISSConfig.load({"security": {"request_timeout_s": 0}})


def test_config_env_overrides():
    config = TIVISSConfig.load_env(
        {
            "TIVISS_SECURITY_MODE": "daemon",
            "TIVISS_SECURITY_SOCKET": "/run/tiviss/custom.sock",
            "TIVISS_SECURITY_TIMEOUT": "1.5",
        }
    )
    assert config.security.mode == "daemon"
    assert config.security.socket_path == "/run/tiviss/custom.sock"
    assert config.security.request_timeout_s == 1.5


def test_create_pdp_embedded_uses_permission_lists():
    config = TIVISSConfig.load(
        {"permissions": {"allow": ["memory.*"], "deny": ["memory.secret"]}}
    )
    pdp = create_pdp(config)
    assert isinstance(pdp, EmbeddedPDP)
    assert isinstance(pdp, PDP)
    assert pdp.allowed("alice", "memory.store", "doc") is True
    assert pdp.allowed("alice", "memory.secret", "doc") is False  # deny wins
    assert pdp.allowed("mallory", "tools.execute", "bin") is False


def test_create_pdp_embedded_default_deny():
    pdp = create_pdp(TIVISSConfig.defaults())
    assert pdp.allowed("alice", "anything", "goes") is False
    response = pdp.decide(make_request("alice", "anything", "goes"))
    assert response.decision.value == "deny"
    assert "default deny" in response.reason


def test_create_pdp_daemon_unavailable_fails_closed(tmp_path):
    config = TIVISSConfig.load(
        {"security": {"mode": "daemon", "socket_path": str(tmp_path / "absent.sock")}}
    )
    pdp = create_pdp(config)
    assert isinstance(pdp, DaemonPDP)
    with pytest.raises(SecurityUnavailableError, match="unavailable"):
        pdp.decide(make_request("a", "b", "c"))
    assert pdp.allowed("a", "b", "c") is False  # fail closed


def test_create_pdp_invalid_mode_raises():
    config = TIVISSConfig.defaults()
    config.security.mode = "yolo"  # bypass loader validation on purpose
    with pytest.raises(SecurityConfigurationError, match="security.mode"):
        create_pdp(config)


def test_make_request_builds_valid_request():
    request = make_request("alice", "memory.store", "doc", context={"k": 1})
    assert request.subject == "alice"
    assert request.action == "memory.store"
    assert request.resource == "doc"
    assert request.context == {"k": 1}
    assert request.request_id
    # Round-trips through the wire schema:
    from tiviss_security_protocol import DecisionRequest

    assert DecisionRequest.from_dict(request.to_dict()) == request


def test_embedded_rejects_non_request():
    pdp = create_pdp(TIVISSConfig.defaults())
    with pytest.raises(TypeError, match="DecisionRequest"):
        pdp.decide({"subject": "a"})  # type: ignore[arg-type]


def test_embedded_rejects_bad_permission_lists():
    from tiviss_security_host import PolicyError

    config = TIVISSConfig.defaults()
    config.permissions.allow = ["memory..bad"]  # bypass validation on purpose
    with pytest.raises(PolicyError, match="action pattern"):
        create_pdp(config)
