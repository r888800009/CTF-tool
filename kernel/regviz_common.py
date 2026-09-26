"""Shared machinery for the kernel register-visualizer GDB plugins.

Each architecture folder (x86_64, arm64, riscv, mips) ships a thin plugin that
calls :func:`install` with its register list; everything else — the web server,
the `sync`/control commands, the reload logic and the register reading — lives
here so the per-arch plugins stay tiny and free of duplicated logic.

The shared web page ``regviz.html`` (next to this module) renders whatever
register schema the arch's ``regs.js`` provides, and the server only ever serves
the *last synced* snapshot: nothing is read from the target until the user runs
``sync`` in gdb.
"""

import http.server
import json
import socket
import threading
import time
import webbrowser
from pathlib import Path

import gdb  # provided by the gdb Python runtime

_VERSION = 1  # bump when this shared implementation changes so re-sourcing hot-reloads
_HTML_PATH = Path(__file__).resolve().parent / "regviz.html"


def _primary_ip():
    """Best-effort LAN IP of this machine, used to print a URL a remote browser
    can reach when the server binds to 0.0.0.0. No packets are actually sent;
    connecting a UDP socket just picks the outbound interface. Falls back to
    loopback when there is no usable route.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _looks_like_host(tok):
    return "." in tok or tok in ("localhost", "::", "::1")


def _parse_host_port(tokens):
    """Parse `[HOST] [PORT]` / `HOST:PORT` argument tokens into (host, port).

    Either may be omitted; missing values come back as None so the caller keeps
    its own defaults.
    """
    host = None
    port = None
    for tok in tokens:
        if tok.isdigit():
            port = int(tok)
        elif ":" in tok:  # host:port
            h, _, p = tok.rpartition(":")
            host = h or host
            if p.isdigit():
                port = int(p)
        else:
            host = tok
    return host, port


def _read_reg(expr):
    """Return a register value as an unsigned int, or None if unavailable.

    Control / system registers are only exposed by gdb when attached to a live
    target (e.g. a QEMU gdb stub); on a plain user-space process the evaluation
    fails, and some targets omit particular registers, so each read is defensive.
    """
    try:
        val = gdb.parse_and_eval(expr)
        return int(val) & 0xFFFFFFFFFFFFFFFF
    except gdb.error:
        return None
    except Exception:  # noqa: BLE001 - never let a bad read abort the sync command
        return None


class _State:
    """Thread-shared snapshot of the last ``sync``."""

    def __init__(self):
        self._lock = threading.Lock()
        self._regs = {}
        self._synced_at = None  # epoch seconds of the last successful sync

    def update(self, regs):
        with self._lock:
            self._regs = dict(regs)
            self._synced_at = time.time()

    def snapshot(self):
        with self._lock:
            # Values are serialized as hex strings so 64-bit registers survive
            # the trip to JavaScript without losing precision to its floats.
            regs = {
                name: (None if val is None else "0x%x" % val)
                for name, val in self._regs.items()
            }
            return {
                "synced": self._synced_at is not None,
                "synced_at": self._synced_at,
                "regs": regs,
            }


def _make_handler():
    class _Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):  # silence the default stderr access log
            pass

        def _send(self, code, body, content_type):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _send_file(self, path, content_type):
            try:
                self._send(200, path.read_bytes(), content_type)
            except OSError as exc:
                self._send(500, str(exc).encode(), "text/plain; charset=utf-8")

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path in ("/", "/index.html", "/regviz.html"):
                self._send_file(_HTML_PATH, "text/html; charset=utf-8")
            elif path == "/regs.js":
                self._send_file(self.server.regs_path, "application/javascript; charset=utf-8")
            elif path == "/data":
                snap = self.server.state.snapshot()
                snap["prefix"] = self.server.prefix  # so the page can show `<prefix> sync`
                body = json.dumps(snap).encode()
                self._send(200, body, "application/json")
            else:
                self._send(404, b"not found", "text/plain; charset=utf-8")

    return _Handler


class Server:
    def __init__(self, prefix, default_port, regs_path, exprs, label):
        self.prefix = prefix
        self.default_port = default_port
        self.regs_path = regs_path
        self.exprs = exprs
        self.label = label
        self.state = _State()
        self._httpd = None
        self._thread = None
        self._version = _VERSION

    @property
    def running(self):
        return self._httpd is not None

    @property
    def url(self):
        if not self._httpd:
            return None
        host, port = self._httpd.server_address[:2]
        if host in ("0.0.0.0", "::"):
            # Bound to every interface (for access from another machine): show a
            # LAN address that a remote browser can actually reach, not loopback.
            host = _primary_ip()
        return "http://%s:%d/" % (host, port)

    def start(self, port=None, host=None, open_browser=True):
        if self._httpd is not None:
            print("[%s] already running on %s" % (self.prefix, self.url))
            return
        port = port or self.default_port
        host = host or "127.0.0.1"
        try:
            httpd = http.server.ThreadingHTTPServer((host, port), _make_handler())
        except OSError as exc:
            print("[%s] could not bind %s:%d — %s" % (self.prefix, host, port, exc))
            return
        httpd.state = self.state
        httpd.regs_path = self.regs_path
        httpd.prefix = self.prefix
        self._httpd = httpd
        # Keep the module stash pointing at the running server so a later
        # re-source reuses it (and `stop` can clear it) rather than colliding.
        setattr(gdb, "_regviz_%s" % self.prefix, self)
        self._thread = threading.Thread(
            target=httpd.serve_forever, name="%s-http" % self.prefix, daemon=True
        )
        self._thread.start()
        print("[%s] serving %s view at %s" % (self.prefix, self.label, self.url))
        if host not in ("127.0.0.1", "localhost", "::1"):
            print("[%s] bound to %s — reachable from other machines on the network"
                  % (self.prefix, host))
        print("[%s] run `%s sync` in gdb to push the current register values"
              % (self.prefix, self.prefix))
        if open_browser:
            try:
                webbrowser.open(self.url)
            except Exception:  # noqa: BLE001 - headless boxes have no browser
                pass

    def stop(self, quiet=False):
        if self._httpd is None:
            if not quiet:
                print("[%s] not running" % self.prefix)
            return
        self._httpd.shutdown()
        self._httpd.server_close()
        self._httpd = None
        self._thread = None
        # Drop the module-level reference so a later re-source rebuilds a fresh
        # server from the newly-loaded code instead of reusing this instance.
        attr = "_regviz_%s" % self.prefix
        if getattr(gdb, attr, None) is self:
            try:
                delattr(gdb, attr)
            except AttributeError:
                pass
        if not quiet:
            print("[%s] stopped" % self.prefix)

    def status(self):
        if self.running:
            snap = self.state.snapshot()
            when = "never" if not snap["synced"] else time.strftime(
                "%H:%M:%S", time.localtime(snap["synced_at"])
            )
            print("[%s] running on %s (last sync: %s)" % (self.prefix, self.url, when))
        else:
            print("[%s] not running" % self.prefix)

    def sync(self):
        regs = {}
        for name, expr in self.exprs:
            # expr may be a single string or a list of candidates to try in
            # order (register names differ between targets, e.g. MIPS CP0 regs).
            candidates = expr if isinstance(expr, (list, tuple)) else [expr]
            value = None
            for cand in candidates:
                value = _read_reg(cand)
                if value is not None:
                    break
            regs[name] = value
        self.state.update(regs)
        parts = ["%s=%s" % (n, "n/a" if v is None else "0x%x" % v) for n, v in regs.items()]
        print("[%s] synced: %s" % (self.prefix, "  ".join(parts)))
        if all(v is None for v in regs.values()):
            print("[%s] no registers were readable — attach to a live target "
                  "(e.g. a QEMU gdb stub) before syncing" % self.prefix)


class _ControlCommand(gdb.Command):
    """Control a register web view.

    Usage: <prefix> [start [HOST] [PORT] | sync | stop | status]

    `<prefix> sync` reads the registers now and pushes them to the page. HOST
    defaults to 127.0.0.1 (loopback only); pass 0.0.0.0 to listen on every
    interface so a browser on another machine can reach it.
    """

    def __init__(self, server):
        super().__init__(server.prefix, gdb.COMMAND_USER)
        self._server = server

    def invoke(self, arg, from_tty):
        tokens = gdb.string_to_argv(arg)
        if not tokens or tokens[0] == "status":
            self._server.status()
            return
        sub = tokens[0]
        if sub == "sync":
            if not self._server.running:
                print("[%s] web view is not running; starting it now" % self._server.prefix)
                self._server.start()
            self._server.sync()
            return
        if sub == "stop":
            self._server.stop()
            return
        if sub in ("start", "restart"):
            rest = tokens[1:]
        elif sub.isdigit() or ":" in sub or _looks_like_host(sub):
            rest = tokens  # `<prefix> 8000` / `<prefix> 0.0.0.0` shorthand
        else:
            print("usage: %s [start [HOST] [PORT] | sync | stop | status]"
                  % self._server.prefix)
            return
        host, port = _parse_host_port(rest)
        self._server.start(port=port, host=host)


def install(*, prefix, default_port, directory, regs_js, exprs, label):
    """Create (or hot-reload) the server for one architecture and register its
    ``<prefix>`` and ``sync`` gdb commands, then auto-start the web view.

    directory / regs_js locate the arch's ``regs.js`` served at ``/regs.js``.
    """
    regs_path = Path(directory).resolve() / regs_js
    attr = "_regviz_%s" % prefix

    prev = getattr(gdb, attr, None)
    if prev is not None and getattr(prev, "_version", 0) != _VERSION:
        try:
            prev.stop(quiet=True)
        except Exception:  # noqa: BLE001
            pass
        prev = None

    if prev is None:
        server = Server(prefix, default_port, regs_path, exprs, label)
        setattr(gdb, attr, server)
    else:
        server = prev
        server.regs_path = regs_path  # pick up a moved/renamed schema on re-source
        server.exprs = exprs

    _ControlCommand(server)

    if not server.running:
        server.start()
    return server
