# tiviss-security-host

Local T.I.V.I.S.S. policy decision point (PDP) — Wave B, runtime model C
("library + local PDP daemon").

- `PolicyEngine` — fail-closed rule evaluation (default **deny**, explicit
  **deny wins** over allow), action patterns like ``memory.*``, optional
  ``subject``/``resource`` fnmatch patterns, thread-safe decision stats.
- `PDPServer` — serves ``pdp.decide`` / ``pdp.health`` / ``pdp.version`` over
  a Unix domain socket (default ``/run/tiviss/security.sock``; see
  ``tiviss-security-ipc`` for resolution order). Unknown message types and
  malformed requests are answered fail-closed.
- ``tiviss-security-pdp`` CLI — run the daemon with inline ``--allow`` /
  ``--deny`` rules or a JSON ``--policy`` file.

Stdlib-only (plus its two sibling packages), Python >= 3.10.

```text
pip install -e TIVISS-HOST/security/protocol \
              -e TIVISS-HOST/security/ipc \
              -e TIVISS-HOST/security/host
python -m pytest -q
tiviss-security-pdp --socket /run/tiviss/security.sock --allow 'memory.*'
```
