"""Client for the in-gdb bridge started by ``gdbmcp.py``.

The MCP server uses this to forward commands into the user's own running gdb. A
fresh connection is opened per request, which keeps the client stateless and
robust against a gdb session being restarted between calls.
"""

from __future__ import annotations

import json
import os
import socket

_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 4577


class BridgeError(RuntimeError):
    """Raised for expected, user-facing bridge errors."""


def _target() -> tuple[str, object]:
    sock_path = os.environ.get("GDBMCP_SOCKET")
    if sock_path:
        return "unix", sock_path
    host = os.environ.get("GDBMCP_HOST", _DEFAULT_HOST)
    port = int(os.environ.get("GDBMCP_PORT", str(_DEFAULT_PORT)))
    return "tcp", (host, port)


def _describe() -> str:
    kind, addr = _target()
    return addr if kind == "unix" else f"{addr[0]}:{addr[1]}"


def _connect(timeout: float) -> socket.socket:
    kind, addr = _target()
    if kind == "unix":
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(addr)
    except OSError as exc:
        s.close()
        raise BridgeError(
            f"Cannot reach the gdb bridge at {_describe()} ({exc}). "
            "In your gdb, run:  source /path/to/mcp/gdb/gdbmcp.py"
        ) from exc
    return s


def request(cmd: str = "", timeout: float = 30.0, op: str | None = None) -> str:
    """Send one request to the in-gdb bridge and return its text output."""
    s = _connect(timeout=5.0)
    payload = {"cmd": cmd, "timeout": timeout}
    if op:
        payload["op"] = op
    try:
        s.settimeout(timeout + 5.0)
        s.sendall((json.dumps(payload) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    except socket.timeout as exc:
        raise BridgeError(f"Timed out waiting for gdb response after {timeout}s.") from exc
    finally:
        s.close()

    if not buf:
        raise BridgeError("gdb bridge closed the connection without responding.")
    try:
        resp = json.loads(buf.split(b"\n", 1)[0].decode())
    except json.JSONDecodeError as exc:
        raise BridgeError(f"Malformed response from gdb bridge: {exc}") from exc

    if not resp.get("ok"):
        raise BridgeError(resp.get("error", "unknown error from gdb bridge"))
    return resp.get("output", "")


def ping() -> str:
    return request(op="ping", timeout=5.0)
