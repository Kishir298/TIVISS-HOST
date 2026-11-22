"""PolicyEngine rule evaluation: fail closed, deny wins."""

from __future__ import annotations

import pytest
from tiviss_security_protocol import Decision, DecisionRequest

from tiviss_security_host import (
    PolicyEngine,
    PolicyError,
    Rule,
    valid_action_pattern,
)


def request(
    subject: str = "alice",
    action: str = "memory.store",
    resource: str = "doc",
) -> DecisionRequest:
    return DecisionRequest(subject=subject, action=action, resource=resource)


def test_default_is_deny_without_rules():
    engine = PolicyEngine()
    decision, reason = engine.decide_detailed(request())
    assert decision is Decision.DENY
    assert "default deny" in reason
    assert engine.stats.snapshot() == {"total": 1, "allow": 0, "deny": 1}


def test_allow_rule_grants_matching_action():
    engine = PolicyEngine.from_permission_lists(allow=["memory.*"])
    assert engine.decide(request(action="memory.store")) is Decision.ALLOW
    assert engine.decide(request(action="memory.forget")) is Decision.ALLOW


def test_non_matching_action_denied():
    engine = PolicyEngine.from_permission_lists(allow=["memory.*"])
    assert engine.decide(request(action="tools.execute")) is Decision.DENY


def test_deny_wins_over_allow():
    engine = PolicyEngine.from_permission_lists(
        allow=["memory.*"], deny=["memory.secret"]
    )
    assert engine.decide(request(action="memory.store")) is Decision.ALLOW
    decision, reason = engine.decide_detailed(request(action="memory.secret"))
    assert decision is Decision.DENY
    assert "explicit deny" in reason


def test_wildcard_allow_covers_every_action():
    engine = PolicyEngine.from_permission_lists(allow=["*"])
    assert engine.decide(request(action="anything.goes")) is Decision.ALLOW


def test_exact_action_match():
    engine = PolicyEngine.from_permission_lists(allow=["memory.store"])
    assert engine.decide(request(action="memory.store")) is Decision.ALLOW
    assert engine.decide(request(action="memory.storer")) is Decision.DENY


def test_subject_pattern_rules():
    engine = PolicyEngine(
        [Rule("allow", action="tools.run", subject="agent-*")]
    )
    assert (
        engine.decide(request(subject="agent-7", action="tools.run"))
        is Decision.ALLOW
    )
    assert (
        engine.decide(request(subject="mallory", action="tools.run"))
        is Decision.DENY
    )


def test_resource_pattern_rules():
    engine = PolicyEngine(
        [Rule("allow", action="memory.read", resource="shared/*")]
    )
    assert (
        engine.decide(request(action="memory.read", resource="shared/notes"))
        is Decision.ALLOW
    )
    assert (
        engine.decide(request(action="memory.read", resource="private/notes"))
        is Decision.DENY
    )


def test_from_policy_full_shape():
    engine = PolicyEngine.from_policy(
        {
            "allow": ["memory.*"],
            "deny": ["memory.secret"],
            "rules": [
                {
                    "effect": "allow",
                    "action": "handover.start",
                    "subject": "owner",
                    "resource": "*",
                }
            ],
        }
    )
    assert engine.decide(request(action="memory.store")) is Decision.ALLOW
    assert engine.decide(request(action="memory.secret")) is Decision.DENY
    assert (
        engine.decide(request(subject="owner", action="handover.start"))
        is Decision.ALLOW
    )
    assert (
        engine.decide(request(subject="intruder", action="handover.start"))
        is Decision.DENY
    )


def test_from_policy_rejects_unknown_keys():
    with pytest.raises(PolicyError, match="unknown policy keys"):
        PolicyEngine.from_policy({"allow": ["x"], "sudo": True})


def test_from_policy_rejects_bad_shapes():
    with pytest.raises(PolicyError, match="'allow' must be a list"):
        PolicyEngine.from_policy({"allow": "memory.*"})
    with pytest.raises(PolicyError, match="must be a JSON object"):
        PolicyEngine.from_policy({"rules": ["memory.*"]})


def test_rule_rejects_invalid_effect():
    with pytest.raises(PolicyError, match="effect"):
        Rule("maybe", action="memory.*")


def test_rule_rejects_invalid_action():
    with pytest.raises(PolicyError, match="action pattern"):
        Rule("allow", action="memory..store")


def test_valid_action_pattern():
    assert valid_action_pattern("memory.store")
    assert valid_action_pattern("memory.*")
    assert valid_action_pattern("*")
    assert not valid_action_pattern("memory.*.store")
    assert not valid_action_pattern("has space")
    assert not valid_action_pattern("")


def test_add_rule_and_rule_validation():
    engine = PolicyEngine()
    engine.add_rule(Rule("allow", action="memory.*"))
    assert engine.decide(request()) is Decision.ALLOW
    with pytest.raises(PolicyError, match="expected Rule"):
        engine.add_rule("memory.*")  # type: ignore[arg-type]


def test_decide_requires_decision_request():
    engine = PolicyEngine()
    with pytest.raises(PolicyError, match="DecisionRequest"):
        engine.decide({"subject": "a"})  # type: ignore[arg-type]


def test_stats_accumulate_across_decisions():
    engine = PolicyEngine.from_permission_lists(allow=["memory.*"])
    engine.decide(request(action="memory.store"))
    engine.decide(request(action="tools.run"))
    engine.decide(request(action="memory.load"))
    assert engine.stats.snapshot() == {"total": 3, "allow": 2, "deny": 1}
