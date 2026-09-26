"""GDB MCP server.

A standalone Model Context Protocol server that forwards commands into a GDB
session the **user opens and controls themselves**. The user launches gdb (with
their own pwndbg/gef/peda setup), then inside it runs:

    (gdb) source /path/to/mcp/gdb/gdbmcp.py

That starts a bridge inside their gdb; this MCP server connects to it and drives
that exact live session — the user's breakpoints, current stop, and plugins.

This server never spawns or kills gdb: the process lifecycle stays with the user.

Run:

    python server.py            # stdio transport (what MCP clients speak)
    gdb-mcp                     # if installed as a package

Transport must match gdbmcp.py (shared env vars):
    GDBMCP_SOCKET / GDBMCP_HOST (default 127.0.0.1) / GDBMCP_PORT (default 4577)
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from bridge import BridgeError, ping, request

mcp = MCPServer("gdb")


def _run(fn):
    try:
        return fn()
    except BridgeError as exc:
        return f"Error: {exc}"


def _out(text: str) -> str:
    text = (text or "").rstrip()
    return text if text else "(no output)"


@mcp.tool()
def gdb_ping() -> str:
    """Check the connection to the user's gdb bridge (gdbmcp.py must be sourced)."""
    return _run(lambda: f"Connected to gdb bridge: {ping()}")


@mcp.tool()
def gdb_command(command: str, timeout_sec: float = 30.0) -> str:
    """Run an arbitrary command in the user's live gdb and return its output.

    This is the general-purpose tool: any gdb command works, including pwndbg /
    gef / peda extensions (e.g. "checksec", "vmmap", "heap", "telescope",
    "search", "canary", "info proc mappings"). Raise timeout_sec for slow commands.

    Note: while the inferior is actively running, gdb cannot service the command
    until it stops; the user may need to interrupt (Ctrl-C) in their gdb terminal.
    """
    return _run(lambda: _out(request(command, timeout=timeout_sec)))


@mcp.tool()
def gdb_break(location: str, condition: str | None = None) -> str:
    """Set a breakpoint at a location (function, file:line, or *address).

    Args:
        location: e.g. "main", "*0x401234", "src.c:42".
        condition: Optional expression for a conditional breakpoint.
    """
    cmd = f"break {location}"
    if condition:
        cmd += f" if {condition}"
    return _run(lambda: _out(request(cmd)))


@mcp.tool()
def gdb_continue(timeout_sec: float = 60.0) -> str:
    """Continue execution until the next stop (breakpoint, signal, or exit)."""
    return _run(lambda: _out(request("continue", timeout=timeout_sec)))


@mcp.tool()
def gdb_run(args: str = "", timeout_sec: float = 60.0) -> str:
    """Start the inferior with optional arguments (gdb `run`).

    For programs that read stdin, prefer setting up input in your own gdb (e.g.
    `run < payload`) and calling gdb_command, since input handling belongs to the
    session the user controls.
    """
    cmd = f"run {args}".strip()
    return _run(lambda: _out(request(cmd, timeout=timeout_sec)))


@mcp.tool()
def gdb_step(count: int = 1, over: bool = False) -> str:
    """Step source lines. over=False steps into calls (step); True steps over (next)."""
    verb = "next" if over else "step"
    return _run(lambda: _out(request(f"{verb} {count}")))


@mcp.tool()
def gdb_stepi(count: int = 1, over: bool = False) -> str:
    """Step machine instructions. over=False uses stepi; True uses nexti."""
    verb = "nexti" if over else "stepi"
    return _run(lambda: _out(request(f"{verb} {count}")))


@mcp.tool()
def gdb_finish(timeout_sec: float = 60.0) -> str:
    """Run until the current function returns."""
    return _run(lambda: _out(request("finish", timeout=timeout_sec)))


@mcp.tool()
def gdb_registers(register: str | None = None) -> str:
    """Show registers. Pass a name (e.g. "rip") for one, else all of them."""
    cmd = f"info registers {register}" if register else "info registers"
    return _run(lambda: _out(request(cmd)))


@mcp.tool()
def gdb_examine(expression: str, count: int = 1, fmt: str = "xw") -> str:
    """Examine memory (gdb `x/`).

    Args:
        expression: Address or expression, e.g. "$rsp", "0x601050", "&buf".
        count: Number of units to display.
        fmt: gdb x/ format+size letters, e.g. "xg" (hex giant), "i" (instr),
            "s" (string).
    """
    return _run(lambda: _out(request(f"x/{count}{fmt} {expression}")))


@mcp.tool()
def gdb_disassemble(location: str = "", count: int | None = None) -> str:
    """Disassemble. Empty location disassembles around the current PC.

    Args:
        location: Function name or address; empty for the current frame.
        count: If set with an address, disassemble that many bytes from it.
    """
    if location and count:
        cmd = f"disassemble {location},+{count}"
    elif location:
        cmd = f"disassemble {location}"
    else:
        cmd = "disassemble"
    return _run(lambda: _out(request(cmd)))


@mcp.tool()
def gdb_backtrace(full: bool = False) -> str:
    """Show the call stack. full=True includes local variables per frame."""
    return _run(lambda: _out(request("backtrace full" if full else "backtrace")))


@mcp.tool()
def gdb_interrupt(timeout_sec: float = 10.0) -> str:
    """Interrupt a running inferior — the AI's equivalent of Ctrl-C in the terminal.

    Use this when the program is running (after gdb_continue/gdb_run, or an
    interactive program like a shell) and other commands would time out. It sends
    SIGINT to gdb so it stops the inferior and returns to the prompt, then reports
    where it stopped, after which normal inspection commands work again.
    """
    return _run(lambda: _out(request(op="interrupt", timeout=timeout_sec)))


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
