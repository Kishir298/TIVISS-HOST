"""``tiviss-security-pdp`` command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from tiviss_security_ipc import IPCError

from .engine import PolicyEngine, Rule
from .errors import PolicyError
from .server import PDPServer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tiviss-security-pdp",
        description=(
            "Run the local T.I.V.I.S.S. policy decision point (PDP) daemon "
            "on a Unix domain socket (default /run/tiviss/security.sock)."
        ),
    )
    parser.add_argument(
        "--socket",
        default=None,
        help="Unix socket path (default: TIVISS_SECURITY_SOCKET or the "
        "standard resolution order)",
    )
    parser.add_argument(
        "--policy",
        default=None,
        metavar="FILE",
        help='JSON policy file: {"allow": [...], "deny": [...], "rules": [...]}',
    )
    parser.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="ACTION",
        help="allow an action pattern (repeatable)",
    )
    parser.add_argument(
        "--deny",
        action="append",
        default=[],
        metavar="ACTION",
        help="deny an action pattern (repeatable; deny wins)",
    )
    parser.add_argument(
        "--quiet", action="store_true", help="do not print the listen address"
    )
    return parser


def build_engine(args: argparse.Namespace) -> PolicyEngine:
    """Construct the engine from ``--policy`` plus inline allow/deny rules."""
    if args.policy:
        raw = json.loads(Path(args.policy).read_text(encoding="utf-8"))
        engine = PolicyEngine.from_policy(raw)
    else:
        engine = PolicyEngine()
    for action in args.allow:
        engine.add_rule(Rule("allow", action=action))
    for action in args.deny:
        engine.add_rule(Rule("deny", action=action))
    return engine


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        engine = build_engine(args)
    except (PolicyError, OSError, json.JSONDecodeError) as exc:
        print(f"tiviss-security-pdp: {exc}", file=sys.stderr)
        return 2
    server = PDPServer(engine, socket_path=args.socket)
    try:
        server.start()
    except (IPCError, OSError) as exc:
        print(f"tiviss-security-pdp: {exc}", file=sys.stderr)
        return 1
    if not args.quiet:
        print(f"tiviss-security-pdp: listening on {server.address}", flush=True)
    try:
        while True:
            time.sleep(0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
