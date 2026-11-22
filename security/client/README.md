# tiviss-security-client

Client for the local T.I.V.I.S.S. PDP daemon (Wave B).  Used by embedders
(T.I.V.I.S.S. runtime, C.O.R.E., R.E.S.C.S.) when
``security.mode = "daemon"``.

- `SecurityClient.decide()` — ask the daemon for an allow/deny decision.
- `SecurityClient.health()` / `version()` — daemon introspection.
- `PDPError` — the daemon answered with a ``pdp.error`` envelope (bad
  request, unknown type, ...).
- Transport failures (`IPCError`) and framing failures (`FrameError`)
  propagate as-is so callers can distinguish "daemon unavailable" from
  "daemon said no".

Stdlib-only (plus its two sibling packages), Python >= 3.10.

```text
pip install -e TIVISS-HOST/security/protocol \
              -e TIVISS-HOST/security/ipc \
              -e TIVISS-HOST/security/client
python -m pytest -q
```
