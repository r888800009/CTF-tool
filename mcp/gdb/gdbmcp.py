"""gdbmcp bridge — source this INSIDE your own running gdb.

    (gdb) source mcp/gdb/gdbmcp.py

This starts a small server inside your gdb process. The gdb-mcp MCP server
connects to it and forwards commands into *this* live session, so an MCP client
(e.g. Claude) drives the exact gdb you are sitting in — your breakpoints, current
stop location, and pwndbg/gef/peda.

Nothing is executed until the MCP side asks for it. Commands run on gdb's main
thread (via the thread-safe gdb.post_event), so they behave exactly as if typed
at the prompt.

Choosing the port / transport
-----------------------------
On source it auto-starts on the resolved default. To pick a port manually, use the
`gdbmcp` command that this file registers:

    (gdb) gdbmcp start 5000       # (re)start the bridge on TCP port 5000
    (gdb) gdbmcp                  # show status
    (gdb) gdbmcp stop             # stop the bridge

You can also fix the port before sourcing, either way works:

    (gdb) set $gdbmcp_port = 5000
    (gdb) source mcp/gdb/gdbmcp.py

Resolution order for the port is: explicit argument to `gdbmcp start` >
environment variable GDBMCP_PORT > gdb convenience variable $gdbmcp_port >
default 4577. Host comes from GDBMCP_HOST / $gdbmcp_host / 127.0.0.1. If
GDBMCP_SOCKET is set, a unix socket is used instead of TCP.

Whatever you choose here, set the matching GDBMCP_HOST/GDBMCP_PORT/GDBMCP_SOCKET
for the MCP server so the two sides agree.

Note: while the inferior is actually running (e.g. after `continue` with no
pending stop), gdb's main thread is busy and queued commands only run once it
stops. Interrupt with Ctrl-C in your gdb terminal as usual.
"""

import errno
import json
import os
import signal
import socket
import threading
import time

import gdb  # provided by gdb's embedded Python; only importable inside gdb

_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 4577
_DEFAULT_TIMEOUT = 30.0


def _conv_var(name):
    """Read a gdb convenience variable ($name), or None if unset."""
    try:
        val = gdb.convenience_variable(name)
    except Exception:  # noqa: BLE001 - older gdb without the API
        return None
    if val is None:
        return None
    try:
        return str(val)
    except Exception:  # noqa: BLE001
        return None


def _resolve_host():
    return os.environ.get("GDBMCP_HOST") or _conv_var("gdbmcp_host") or _DEFAULT_HOST


def _resolve_port():
    raw = os.environ.get("GDBMCP_PORT") or _conv_var("gdbmcp_port")
    if raw is None:
        return _DEFAULT_PORT
    try:
        return int(str(raw).strip())
    except ValueError:
        print(f"[gdbmcp] invalid port {raw!r}; using {_DEFAULT_PORT}")
        return _DEFAULT_PORT


def _any_thread_running():
    try:
        inf = gdb.selected_inferior()
        return any(t.is_running() for t in inf.threads())
    except gdb.error as exc:
        # Remote/qemu stubs refuse thread queries while the target is running,
        # raising "Cannot execute this command while the target is running." That
        # message is itself proof that it IS running, so report True.
        if "target is running" in str(exc).lower():
            return True
        return False
    except Exception:  # noqa: BLE001
        return False


def _stop_summary():
    """A concise, human/agent-friendly description of the current stop."""
    try:
        frame = gdb.selected_frame()
    except Exception:  # noqa: BLE001 - no frame (e.g. just after exit)
        return "[stopped]"
    try:
        pc = int(frame.pc())
        name = frame.name() or "??"
        sal = frame.find_sal()
        line = sal.line if sal and sal.line else 0
        loc = f"0x{pc:x} in {name}"
        if line:
            loc += f" (line {line})"
        return f"[stopped] {loc}"
    except Exception:  # noqa: BLE001
        return "[stopped]"


def _run_on_main(command, timeout):
    """Schedule `command` on gdb's main thread and wait for its text output.

    Execution commands (run/continue/step/finish/...) are special: when driven
    from inside a posted event, gdb.execute resumes the inferior asynchronously
    and returns *before* the real stop. We detect the still-running inferior and
    wait for the stop/exit event before reporting, so callers see the true state.
    """
    box = {}
    done = threading.Event()

    def finish(text=None, error=None):
        if error is not None:
            box["error"] = error
        elif text is not None:
            box["output"] = (box.get("output", "") + "\n" + text).strip()
        done.set()

    def task():
        # Handlers must be resolvable before they reference each other.
        handlers = {}

        def cleanup():
            for evt_name, fn in handlers.items():
                try:
                    getattr(gdb.events, evt_name).disconnect(fn)
                except Exception:  # noqa: BLE001
                    pass

        def on_stop(_event):
            if done.is_set():
                return
            cleanup()
            finish(text=_stop_summary())

        def on_exit(event):
            if done.is_set():
                return
            cleanup()
            code = getattr(event, "exit_code", None)
            msg = "[inferior exited]" if code is None else f"[inferior exited with code {code}]"
            finish(text=msg)

        handlers["stop"] = on_stop
        handlers["exited"] = on_exit

        try:
            box["output"] = gdb.execute(command, from_tty=False, to_string=True) or ""
        except gdb.error as exc:
            finish(error=str(exc))
            return
        except Exception as exc:  # noqa: BLE001 - report anything cleanly
            finish(error=f"{type(exc).__name__}: {exc}")
            return

        if _any_thread_running():
            # Resumed asynchronously; wait for the real stop/exit to report state.
            gdb.events.stop.connect(on_stop)
            gdb.events.exited.connect(on_exit)
            return  # returning lets the event loop drive the inferior to its stop
        done.set()

    gdb.post_event(task)  # thread-safe; runs when gdb next services its event loop
    if not done.wait(timeout):
        return {
            "ok": False,
            "error": (
                "timeout: the command did not settle in "
                f"{timeout}s. The inferior may still be running — interrupt it "
                "(Ctrl-C in the gdb terminal) so gdb returns to the prompt, or "
                "raise the timeout."
            ),
        }
    if "error" in box:
        return {"ok": False, "error": box["error"]}
    return {"ok": True, "output": box.get("output", "")}


def _interrupt(timeout):
    """Interrupt a running inferior, mimicking Ctrl-C at the gdb terminal.

    Two mechanisms are used together to cover both gdb configurations:

    * async / non-stop gdb still services posted events while the inferior runs,
      so we post `interrupt`, which asks gdb to stop the target.
    * all-stop synchronous gdb blocks its main thread in the kernel while the
      inferior runs, so posted events cannot fire; there, a SIGINT to gdb's own
      process reaches gdb's C-level handler directly (Python can't intercept it
      because the main thread is not running Python bytecode) and stops the target.

    The two mechanisms are applied in phases, not together: sending SIGINT while
    the posted `interrupt` is in flight can have gdb's embedded Python turn the
    signal into a KeyboardInterrupt that aborts the interrupt. So we try the posted
    `interrupt` first and only fall back to SIGINT if the target has not stopped.

    We wait for the real stop/exit event before reporting where we landed.
    """
    box = {}
    done = threading.Event()

    def task():
        handlers = {}

        def cleanup():
            for name, fn in handlers.items():
                try:
                    getattr(gdb.events, name).disconnect(fn)
                except Exception:  # noqa: BLE001
                    pass

        def on_stop(_event):
            if done.is_set():
                return
            cleanup()
            box["output"] = _stop_summary()
            done.set()

        def on_exit(_event):
            if done.is_set():
                return
            cleanup()
            box["output"] = "[inferior exited]"
            done.set()

        if not _any_thread_running():  # already stopped — nothing to interrupt
            box["output"] = _stop_summary()
            done.set()
            return

        handlers["stop"] = on_stop
        handlers["exited"] = on_exit
        gdb.events.stop.connect(on_stop)
        gdb.events.exited.connect(on_exit)
        try:
            gdb.execute("interrupt", from_tty=False, to_string=True)
        except gdb.error:
            pass  # SIGINT fallback below

    gdb.post_event(task)

    # Phase 1: let the posted `interrupt` work (async / non-stop gdb).
    phase1 = min(2.0, timeout)
    if not done.wait(phase1):
        # Phase 2: the posted event likely cannot fire (synchronous gdb, main
        # thread blocked in the kernel). SIGINT reaches gdb's C handler directly.
        try:
            os.kill(os.getpid(), signal.SIGINT)
        except Exception:  # noqa: BLE001
            pass
        if not done.wait(max(0.0, timeout - phase1)):
            return {
                "ok": True,
                "output": "[interrupt sent] gdb has not returned to the prompt yet; "
                          "retry an inspection command (e.g. gdb_backtrace) shortly.",
            }
    out = box.get("output", "")
    if out.startswith("[stopped]"):
        out = "[interrupted]" + out[len("[stopped]"):]
    else:
        out = f"[interrupted] {out}".rstrip()
    return {"ok": True, "output": out}


def _handle_request(req):
    op = req.get("op")
    if op == "ping":
        return {"ok": True, "output": "pong"}
    if op == "interrupt":
        return _interrupt(float(req.get("timeout", _DEFAULT_TIMEOUT)))
    command = req.get("cmd", "")
    if not command:
        return {"ok": False, "error": "empty command"}
    timeout = float(req.get("timeout", _DEFAULT_TIMEOUT))
    return _run_on_main(command, timeout)


def _handle_client(conn):
    with conn:
        stream = conn.makefile("rwb")
        for raw in stream:
            raw = raw.strip()
            if not raw:
                continue
            try:
                resp = _handle_request(json.loads(raw.decode()))
            except Exception as exc:  # noqa: BLE001
                resp = {"ok": False, "error": f"bad request: {exc}"}
            stream.write((json.dumps(resp) + "\n").encode())
            stream.flush()


class _Bridge:
    """Owns the current listening socket so it can be (re)started and stopped."""

    def __init__(self):
        self._srv = None
        self._thread = None
        self.addr = None

    @property
    def running(self):
        return self._srv is not None

    def _make_server(self, host, port, sock_path):
        if sock_path:
            try:
                os.unlink(sock_path)
            except FileNotFoundError:
                pass
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(sock_path)
            return srv, sock_path
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        return srv, f"{host}:{port}"

    def _serve(self, srv):
        srv.listen(8)
        srv.settimeout(0.5)  # so we periodically notice being swapped out / stopped
        while True:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                if self._srv is not srv:  # a newer listener replaced us, or we stopped
                    break
                continue
            except OSError:
                break  # socket closed
            conn.settimeout(None)
            threading.Thread(target=_handle_client, args=(conn,), daemon=True).start()
        try:
            srv.close()
        except OSError:
            pass

    def start(self, port=None, host=None, quiet=False):
        sock_path = os.environ.get("GDBMCP_SOCKET")
        host = host or _resolve_host()
        port = port if port is not None else _resolve_port()
        target = sock_path if sock_path else f"{host}:{port}"

        # Already listening on exactly this address: do nothing. Rebinding the same
        # port would fail with EADDRINUSE, and tearing the listener down first would
        # leave the bridge dead — so re-running `gdbmcp start` must be a safe no-op.
        if self.running and self.addr == target:
            if not quiet:
                print(f"[gdbmcp] already listening on {self.addr} "
                      f"(gdbmcp start <PORT> to move it, gdbmcp stop to stop)")
            return

        # Bind the NEW socket before touching the old one, so a failed (re)bind
        # never leaves us with no listener. Retry briefly on EADDRINUSE: a listener
        # we just stopped (or one from a previous source) can take a moment to be
        # released by the OS, and re-sourcing should not lose that race.
        srv = addr = None
        last_exc = None
        for attempt in range(10):  # ~1.8s total
            try:
                srv, addr = self._make_server(host, port, sock_path)
                break
            except OSError as exc:
                last_exc = exc
                if exc.errno != errno.EADDRINUSE:
                    break
                time.sleep(0.2)
        if srv is None:
            where = f" on {self.addr}" if self.running else ""
            print(f"[gdbmcp] failed to bind {target} ({last_exc}). The current bridge"
                  f"{where} is left running. Pick another port: gdbmcp start <PORT>")
            return

        old = self._srv
        self._srv = srv
        self.addr = addr
        self._thread = threading.Thread(target=self._serve, args=(srv,), daemon=True)
        self._thread.start()
        if old is not None:  # now safe to drop the previous listener
            try:
                old.close()
            except OSError:
                pass
        if not quiet:
            print(f"[gdbmcp] bridge listening on {addr} — the gdb-mcp server can now "
                  f"attach. (change with: gdbmcp start <PORT>)")

    def stop(self, quiet=False):
        if not self.running:
            if not quiet:
                print("[gdbmcp] not running")
            return
        try:
            self._srv.close()
        except OSError:
            pass
        self._srv = None
        addr, self.addr = self.addr, None
        if not quiet:
            print(f"[gdbmcp] stopped ({addr})")

    def status(self):
        if self.running:
            print(f"[gdbmcp] running on {self.addr}")
        else:
            print("[gdbmcp] not running")


_VERSION = 8  # bump when the bridge implementation changes so re-sourcing hot-reloads


class _GdbmcpCommand(gdb.Command):
    """Control the gdbmcp bridge: gdbmcp [start [PORT] | stop | status]."""

    def __init__(self):
        super().__init__("gdbmcp", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        tokens = gdb.string_to_argv(arg)
        if not tokens or tokens[0] == "status":
            _bridge.status()
            return
        sub = tokens[0]
        if sub == "stop":
            _bridge.stop()
            return
        if sub in ("start", "restart"):
            rest = tokens[1:]
        elif sub.isdigit():
            rest = tokens  # `gdbmcp 5000` shorthand
        else:
            print("usage: gdbmcp [start [PORT] | stop | status]")
            return
        port = None
        host = None
        for tok in rest:
            if tok.isdigit():
                port = int(tok)
            elif ":" in tok:  # host:port
                h, _, p = tok.partition(":")
                host = h or None
                port = int(p) if p.isdigit() else port
            else:
                host = tok
        _bridge.start(port=port, host=host)


# A single bridge per gdb process, stashed on the gdb module so re-sourcing reuses a
# still-current one — but an older version is replaced in place, so `source`ing an
# updated gdbmcp.py actually loads the new code (keeping the same port).
_prev = getattr(gdb, "_gdbmcp_bridge", None)
if _prev is not None and getattr(_prev, "_version", 0) != _VERSION:
    try:
        _prev.stop(quiet=True)
    except Exception:  # noqa: BLE001
        pass
    _prev = None

if _prev is None:
    _bridge = _Bridge()
    _bridge._version = _VERSION
    gdb._gdbmcp_bridge = _bridge
else:
    _bridge = _prev

# (Re)register the command so it binds to THIS source's _bridge, replacing any command
# left by an earlier source (gdb replaces a user command of the same name).
_GdbmcpCommand()

# Auto-start on the resolved default so a bare `source` just works.
if not _bridge.running:
    _bridge.start()
else:
    print(f"[gdbmcp] already running on {_bridge.addr} (gdbmcp start <PORT> to change)")
