"""Channel request/response conversations over real sockets."""

from __future__ import annotations

import socket
import struct
import threading
from pathlib import Path

import pytest
from tiviss_security_protocol import FrameError, envelope

from tiviss_security_ipc import Channel, prepare_listener, request_once, unlink_socket


def test_channel_roundtrip_over_socketpair():
    left, right = socket.socketpair()
    try:
        with Channel(left) as sender, Channel(right) as receiver:
            message = envelope("pdp.decide", {"subject": "alice"})
            sender.send(message)
            got = receiver.recv()
            assert got["v"] == message["v"]
            assert got["id"] == message["id"]
            assert got["type"] == "pdp.decide"
            assert got["payload"] == {"subject": "alice"}
    finally:
        left.close()
        right.close()


def test_request_waits_for_matching_response():
    left, right = socket.socketpair()

    def serve() -> None:
        with Channel(right) as server:
            request = server.recv()
            server.send(
                envelope(request["type"], {"ok": True}, msg_id=request["id"])
            )

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        with Channel(left) as client:
            response = client.request(envelope("pdp.health", {}), timeout=2.0)
            assert response["payload"] == {"ok": True}
    finally:
        thread.join(timeout=2)
        left.close()


def test_request_times_out_without_response():
    left, right = socket.socketpair()
    try:
        with Channel(left) as client, pytest.raises(TimeoutError):
            client.request(envelope("pdp.health", {}), timeout=0.2)
    finally:
        left.close()
        right.close()


def test_close_is_idempotent():
    left, right = socket.socketpair()
    try:
        channel = Channel(left)
        channel.close()
        channel.close()
        assert channel.closed
    finally:
        right.close()


def test_recv_rejects_oversized_frame_header():
    left, right = socket.socketpair()
    try:
        with Channel(right) as receiver:
            left.sendall(struct.pack(">I", 10_000_000))
            with pytest.raises(FrameError, match="exceeds limit"):
                receiver.recv()
    finally:
        left.close()
        right.close()


def test_recv_fails_closed_on_mid_frame_eof():
    left, right = socket.socketpair()
    try:
        with Channel(right) as receiver:
            left.sendall(struct.pack(">I", 8) + b"ab")
            left.shutdown(socket.SHUT_WR)
            with pytest.raises(FrameError, match="closed mid-frame"):
                receiver.recv()
    finally:
        left.close()
        right.close()


def test_request_once_roundtrip(sock_dir: Path):
    path = sock_dir / "s.sock"
    listener = prepare_listener(path)

    def serve() -> None:
        conn, _ = listener.accept()
        with Channel(conn) as server:
            request = server.recv()
            server.send(
                envelope(request["type"], {"pong": 1}, msg_id=request["id"])
            )

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        response = request_once(path, envelope("pdp.version", {}), timeout=2.0)
        assert response["payload"] == {"pong": 1}
    finally:
        thread.join(timeout=2)
        listener.close()
        unlink_socket(path)
