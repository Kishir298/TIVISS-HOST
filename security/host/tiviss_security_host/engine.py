"""Fail-closed policy engine for PDP decisions.

Evaluation order (deny wins):
  1. If any matching rule has ``effect=deny`` -> DENY.
  2. Else if any matching rule has ``effect=allow`` -> ALLOW.
  3. Else the engine default applies (``Decision.DENY`` unless explicitly
     constructed otherwise — fail closed).

Action patterns follow the T.I.V.I.S.S. permission grammar: a concrete name
(``memory.store``), a trailing wildcard (``memory.*``), or bare ``*`` for
"every action".  ``subject`` and ``resource`` use fnmatch patterns where
``*`` matches any characters (including ``.``).
"""

from __future__ import annotations

import fnmatch
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from tiviss_security_protocol import Decision, DecisionRequest

from .errors import PolicyError

EFFECT_ALLOW = "allow"
EFFECT_DENY = "deny"
_EFFECTS = {EFFECT_ALLOW, EFFECT_DENY}


def valid_action_pattern(name: str) -> bool:
    """True when ``name`` is a valid permission-style action pattern."""
    if not isinstance(name, str) or not name.strip():
        return False
    parts = name.split(".")
    if not all(part.isidentifier() or part == "*" for part in parts):
        return False
    return not any(part == "*" for part in parts[:-1])


def _action_matches(pattern: str, action: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith(".*"):
        return action.startswith(pattern[:-1])
    return action == pattern


@dataclass(frozen=True)
class Rule:
    """One allow/deny rule over (subject, action, resource)."""

    effect: str
    action: str
    subject: str = "*"
    resource: str = "*"

    def __post_init__(self) -> None:
        if self.effect not in _EFFECTS:
            raise PolicyError(
                f"rule effect must be 'allow' or 'deny', got {self.effect!r}"
            )
        if not valid_action_pattern(self.action):
            raise PolicyError(f"invalid action pattern: {self.action!r}")
        if not isinstance(self.subject, str) or not self.subject:
            raise PolicyError("rule subject must be a non-empty string")
        if not isinstance(self.resource, str) or not self.resource:
            raise PolicyError("rule resource must be a non-empty string")

    @property
    def description(self) -> str:
        parts = [f"action={self.action}"]
        if self.subject != "*":
            parts.append(f"subject={self.subject}")
        if self.resource != "*":
            parts.append(f"resource={self.resource}")
        return f"{self.effect} rule ({', '.join(parts)})"

    def matches(self, subject: str, action: str, resource: str) -> bool:
        if not _action_matches(self.action, action):
            return False
        if not fnmatch.fnmatchcase(subject, self.subject):
            return False
        return fnmatch.fnmatchcase(resource, self.resource)


@dataclass
class EngineStats:
    """Thread-safe decision counters (used by ``pdp.health``)."""

    total: int = 0
    allowed: int = 0
    denied: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record(self, decision: Decision) -> None:
        with self._lock:
            self.total += 1
            if decision is Decision.ALLOW:
                self.allowed += 1
            else:
                self.denied += 1

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {"total": self.total, "allow": self.allowed, "deny": self.denied}


class PolicyEngine:
    """Evaluate :class:`Rule` sets against protocol decision requests."""

    def __init__(
        self,
        rules: Iterable[Rule] = (),
        *,
        default: Decision = Decision.DENY,
    ) -> None:
        if not isinstance(default, Decision):
            raise PolicyError(f"engine default must be a Decision, got {default!r}")
        self._rules: list[Rule] = list(rules)
        self._default = default
        self._lock = threading.Lock()
        self.stats = EngineStats()

    @property
    def default(self) -> Decision:
        return self._default

    @property
    def rules(self) -> tuple[Rule, ...]:
        with self._lock:
            return tuple(self._rules)

    @classmethod
    def from_permission_lists(
        cls, allow: Iterable[str] = (), deny: Iterable[str] = ()
    ) -> PolicyEngine:
        """Build an engine from permission-style action patterns."""
        rules = [Rule(EFFECT_ALLOW, action=name) for name in allow]
        rules += [Rule(EFFECT_DENY, action=name) for name in deny]
        return cls(rules)

    @classmethod
    def from_policy(cls, data: Mapping[str, Any]) -> PolicyEngine:
        """Build an engine from a ``{"allow": [...], "deny": [...],
        "rules": [{"effect", "action", "subject?", "resource?"}]}`` mapping."""
        if not isinstance(data, Mapping):
            raise PolicyError("policy must be a JSON object")
        unknown = set(data) - {"allow", "deny", "rules"}
        if unknown:
            raise PolicyError(f"unknown policy keys: {sorted(unknown)}")
        allow = data.get("allow", [])
        deny = data.get("deny", [])
        raw_rules = data.get("rules", [])
        if not isinstance(allow, list) or not all(
            isinstance(item, str) for item in allow
        ):
            raise PolicyError("policy 'allow' must be a list of strings")
        if not isinstance(deny, list) or not all(
            isinstance(item, str) for item in deny
        ):
            raise PolicyError("policy 'deny' must be a list of strings")
        if not isinstance(raw_rules, list):
            raise PolicyError("policy 'rules' must be a list")
        rules = [Rule(EFFECT_ALLOW, action=name) for name in allow]
        rules += [Rule(EFFECT_DENY, action=name) for name in deny]
        for entry in raw_rules:
            if not isinstance(entry, Mapping):
                raise PolicyError("each policy rule must be a JSON object")
            unknown_rule = set(entry) - {"effect", "action", "subject", "resource"}
            if unknown_rule:
                raise PolicyError(f"unknown rule keys: {sorted(unknown_rule)}")
            try:
                rules.append(
                    Rule(
                        effect=str(entry.get("effect", "")),
                        action=str(entry.get("action", "")),
                        subject=str(entry.get("subject", "*")),
                        resource=str(entry.get("resource", "*")),
                    )
                )
            except TypeError as exc:
                raise PolicyError(f"invalid rule: {exc}") from exc
        return cls(rules)

    def add_rule(self, rule: Rule) -> None:
        if not isinstance(rule, Rule):
            raise PolicyError(f"expected Rule, got {type(rule).__name__}")
        with self._lock:
            self._rules.append(rule)

    def decide(self, request: DecisionRequest) -> Decision:
        decision, _reason = self.decide_detailed(request)
        return decision

    def decide_detailed(self, request: DecisionRequest) -> tuple[Decision, str]:
        """Evaluate ``request``; returns ``(decision, human-readable reason)``."""
        if not isinstance(request, DecisionRequest):
            raise PolicyError(f"expected DecisionRequest, got {type(request).__name__}")
        with self._lock:
            rules = tuple(self._rules)
        subject, action, resource = request.subject, request.action, request.resource
        reason = ""
        decision = self._default
        deny_rule = next(
            (
                rule
                for rule in rules
                if rule.effect == EFFECT_DENY
                and rule.matches(subject, action, resource)
            ),
            None,
        )
        if deny_rule is not None:
            decision, reason = Decision.DENY, f"explicit deny: {deny_rule.description}"
        else:
            allow_rule = next(
                (
                    rule
                    for rule in rules
                    if rule.effect == EFFECT_ALLOW
                    and rule.matches(subject, action, resource)
                ),
                None,
            )
            if allow_rule is not None:
                decision = Decision.ALLOW
                reason = f"explicit allow: {allow_rule.description}"
            else:
                reason = (
                    "default deny (no matching rule)"
                    if decision is Decision.DENY
                    else "default allow (no matching rule)"
                )
        self.stats.record(decision)
        return decision, reason


__all__ = [
    "EFFECT_ALLOW",
    "EFFECT_DENY",
    "PolicyError",
    "Rule",
    "EngineStats",
    "PolicyEngine",
    "valid_action_pattern",
]
