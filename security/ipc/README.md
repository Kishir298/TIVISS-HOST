# tiviss-security-ipc

Unix-domain-socket transport for the T.I.V.I.S.S. security PDP (Wave B).

- `resolve_socket_path()` — explicit arg > `TIVISS_SECURITY_SOCKET` env >
  `/run/tiviss/security.sock` (when writable) > `$XDG_RUNTIME_DIR/tiviss` >
  temp-dir fallback.
- `prepare_listener()` — creates the parent dir (0700 when we created it),
  replaces stale socket files, refuses non-socket paths, binds with 0600.
- `connect()` — fail-closed connect with timeout.
- `Channel` — request/response conversations using the
  `tiviss-security-protocol` framing.
- `peer_credentials()` — peer (pid, uid, gid) where the platform exposes
  them (`SO_PEERCRED`), `None` otherwise.

Stdlib-only, Python >= 3.10.

```text
pip install -e TIVISS-HOST/security/protocol -e TIVISS-HOST/security/ipc
python -m pytest -q
```
