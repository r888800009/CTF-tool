# gdb-mcp

Standalone [MCP](https://modelcontextprotocol.io) server that attaches to **your
own running GDB** so an MCP client (e.g. Claude / Claude Code) can drive it: set
breakpoints, run, inspect registers and memory, disassemble, and run arbitrary
GDB / **pwndbg / gef / peda** commands — in the exact session you are sitting in.

The design is deliberate: **you** open gdb and **you** `source` the bridge. The
MCP server never spawns or kills gdb; it only forwards commands into the live
session, so your breakpoints, current stop, and plugins all stay yours.

This tool is **decoupled** from the rest of the CTF-tool repo (its own deps, its
own virtualenv, no imports from the parent project).

## How it works

```
your terminal:  gdb ./chall   ──(gdb) source gdbmcp.py──▶  bridge listens (TCP/unix)
                                                                    ▲
MCP client (Claude) ──▶ gdb-mcp server (server.py) ──── connects ───┘
```

- `gdbmcp.py` runs inside your gdb's Python. Commands are executed on gdb's main
  thread via the thread-safe `gdb.post_event`, so they behave exactly as if typed
  at the prompt.
- `server.py` is the MCP server; `bridge.py` is its client to the in-gdb bridge.

## Requirements

- Python >= 3.10 for the MCP server (only depends on `mcp`)
- A `gdb` with embedded Python (standard); pwndbg / gef / peda optional but nice

## Install (MCP server side)

```bash
cd mcp/gdb
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
# or as a package exposing the `gdb-mcp` command:
.venv/bin/pip install .
```

## Usage

1. Start (or already have) gdb open and source the bridge (path relative to
   wherever you launched gdb, or absolute on your machine):

   ```text
   $ gdb ./chall
   (gdb) source mcp/gdb/gdbmcp.py
   [gdbmcp] bridge listening on 127.0.0.1:4577 — the gdb-mcp server can now attach.
   ```

   Tip: add the `source` line to `~/.gdbinit` to load it automatically.

   **Choosing the port manually.** Sourcing registers a `gdbmcp` command:

   ```text
   (gdb) gdbmcp start 5000      # move the bridge to TCP port 5000
   (gdb) gdbmcp start 0.0.0.0:5000
   (gdb) gdbmcp status          # show current bind address
   (gdb) gdbmcp stop            # stop the bridge
   ```

   Running `gdbmcp start` again with no port (or the same port) is a safe no-op —
   it does not disturb the already-listening bridge. Re-`source`ing the file also
   keeps the existing bridge and hot-reloads updated code.

   Or fix it before sourcing — any of these work, resolved in this order:
   explicit `gdbmcp start` arg > `GDBMCP_PORT` env > gdb `$gdbmcp_port` > 4577.

   ```text
   (gdb) set $gdbmcp_port = 5000
   (gdb) source mcp/gdb/gdbmcp.py
   ```

   Whatever you pick, set the **matching** `GDBMCP_PORT` (or `GDBMCP_HOST` /
   `GDBMCP_SOCKET`) for the MCP server so both sides agree.

2. Run the MCP server (your client normally launches this for you):

   ```bash
   .venv/bin/python server.py      # stdio transport
   ```

3. Ask the client to debug. It talks to *your* gdb. Try `gdb_ping` first.

### Register with Claude Code

Run from the repo root (or substitute your own absolute paths):

```bash
claude mcp add gdb -- ./mcp/gdb/.venv/bin/python ./mcp/gdb/server.py
```

### Generic `mcpServers` JSON

Paths are relative to the repo root — adjust to your setup:

```json
{
  "mcpServers": {
    "gdb": {
      "command": "./mcp/gdb/.venv/bin/python",
      "args": ["./mcp/gdb/server.py"]
    }
  }
}
```

## Transport / config

Both sides read the same env vars, so they must agree:

| Var | Default | Meaning |
| --- | --- | --- |
| `GDBMCP_SOCKET` | (unset) | If set, use this unix socket path instead of TCP |
| `GDBMCP_HOST` | `127.0.0.1` | TCP bind/connect host |
| `GDBMCP_PORT` | `4577` | TCP bind/connect port |

For gdb inside Docker, publish the port (`docker run -p 4577:4577 ...`) or share a
unix socket via a mounted volume with `GDBMCP_SOCKET`.

## Tools

| Tool | Purpose |
| --- | --- |
| `gdb_ping` | Verify the bridge is reachable (gdbmcp.py sourced). |
| `gdb_command` | Run **any** gdb/pwndbg/gef/peda command (general escape hatch). |
| `gdb_break` | Set a breakpoint, optional condition. |
| `gdb_run` | `run` the inferior with optional args. |
| `gdb_continue` | Continue to next stop. |
| `gdb_step` / `gdb_stepi` | Step source lines / instructions (into or over). |
| `gdb_finish` | Run until current function returns. |
| `gdb_registers` | Dump registers (all or one). |
| `gdb_examine` | Examine memory (`x/`). |
| `gdb_disassemble` | Disassemble a function/address or around PC. |
| `gdb_backtrace` | Show the call stack (optionally with locals). |
| `gdb_interrupt` | Stop a running inferior — the AI's Ctrl-C (for hangs / interactive programs). |

`gdb_command` is the power tool — `checksec`, `vmmap`, `heap`, `telescope`,
`search`, `canary`, `set`, etc. all go through it.

## Notes

- While the inferior is actively running (`continue` with no pending stop), gdb's
  main thread is busy and queued commands only run once it stops. Interrupt with
  Ctrl-C in your gdb terminal.
- One bridge per gdb process. Re-sourcing in the same session is a no-op.
