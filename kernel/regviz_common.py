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
import re
import socket
import threading
import time
import webbrowser
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import gdb  # provided by the gdb Python runtime

_VERSION = 6  # bump when this shared implementation changes so re-sourcing hot-reloads
_HTML_PATH = Path(__file__).resolve().parent / "regviz.html"
_CSS_PATH = Path(__file__).resolve().parent / "regviz.css"  # shared theme for every app


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


def _run_on_main(command, timeout=5.0):
    """Run a gdb command on gdb's main thread and return its text output.

    The web server runs in a background thread and the gdb Python API is not
    thread-safe, so on-demand reads (triggered by clicks in the browser) must be
    marshalled onto gdb's main thread with gdb.post_event, which runs the task
    when gdb next services its event loop — i.e. while stopped at the prompt. If
    the inferior is running the task cannot run and the call times out.
    """
    box = {}
    done = threading.Event()

    def task():
        try:
            box["output"] = gdb.execute(command, from_tty=False, to_string=True) or ""
            box["ok"] = True
        except gdb.error as exc:
            box["ok"] = False
            box["error"] = str(exc)
        except Exception as exc:  # noqa: BLE001
            box["ok"] = False
            box["error"] = "%s: %s" % (type(exc).__name__, exc)
        finally:
            done.set()

    try:
        gdb.post_event(task)  # thread-safe; runs on the main thread at the prompt
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": "post_event failed: %s" % exc}
    if not done.wait(timeout):
        return {"ok": False,
                "error": "timeout after %ss — is gdb stopped at the prompt "
                         "(not running the inferior)?" % timeout}
    return box


def call_on_main(fn, timeout=5.0):
    """Run an arbitrary callable on gdb's main thread and return
    {"ok": True, "result": ...} or {"ok": False, "error": ...}.

    App routes (which run on the web-server thread) use this to touch the
    thread-unsafe gdb API — e.g. reading memory on demand from the browser.
    """
    box = {}
    done = threading.Event()

    def task():
        try:
            box["result"] = fn()
            box["ok"] = True
        except gdb.error as exc:
            box["ok"] = False
            box["error"] = str(exc)
        except Exception as exc:  # noqa: BLE001
            box["ok"] = False
            box["error"] = "%s: %s" % (type(exc).__name__, exc)
        finally:
            done.set()

    try:
        gdb.post_event(task)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": "post_event failed: %s" % exc}
    if not done.wait(timeout):
        return {"ok": False, "error": "timeout after %ss — is gdb at the prompt?" % timeout}
    return box


def _read_phys_qwords(phys, count):
    """Read `count` little-endian 8-byte words at physical address `phys`.

    Uses the QEMU monitor (`monitor xp/<n>gx <addr>`), so it needs a QEMU gdb
    stub. Returns {"ok": True, "values": ["0x..", ...]} or {"ok": False, "error"}.
    """
    cmd = "monitor xp/%dgx 0x%x" % (count, phys)
    res = _run_on_main(cmd)
    if not res.get("ok"):
        return res
    out = res.get("output", "")
    # Monitor lines look like `0000...1000: 0x.... 0x....`; the address prefix has
    # no 0x, so grabbing every 0x-token yields exactly the word values in order.
    vals = re.findall(r"0x([0-9a-fA-F]+)", out)
    if not vals:
        return {"ok": False,
                "error": "no data from `%s` — is this a QEMU target with a "
                         "monitor? output: %s" % (cmd, out.strip()[:200])}
    return {"ok": True, "values": ["0x" + v for v in vals[:count]]}


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
    """Thread-shared snapshot of the last ``sync``: an arbitrary JSON payload
    plus a timestamp, read by the page over /data."""

    def __init__(self):
        self._lock = threading.Lock()
        self._payload = {}
        self._synced_at = None  # epoch seconds of the last successful sync

    def set(self, payload):
        with self._lock:
            self._payload = dict(payload)
            self._synced_at = time.time()

    def snapshot(self):
        with self._lock:
            snap = {"synced": self._synced_at is not None, "synced_at": self._synced_at}
            snap.update(self._payload)
            return snap


_CTYPES = {
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".json": "application/json",
}


def _ctype_for(path):
    for ext, ct in _CTYPES.items():
        if path.endswith(ext):
            return ct
    return "application/octet-stream"


def _make_handler():
    class _Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):  # silence the default stderr access log
            pass

        def _send(self, code, body, content_type):
            if isinstance(body, str):
                body = body.encode()
            try:
                self.send_response(code)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass  # the browser navigated away / aborted the request — ignore

        def _send_file(self, path, content_type):
            try:
                self._send(200, Path(path).read_bytes(), content_type)
            except OSError as exc:
                self._send(500, str(exc).encode(), "text/plain; charset=utf-8")

        def do_GET(self):
            app = self.server.app
            path = self.path.split("?", 1)[0]
            if path in ("/", "/index.html"):
                self._send_file(app.html_path, "text/html; charset=utf-8")
            elif path in app.static:
                self._send_file(app.static[path], _ctype_for(path))
            elif path == "/data":
                snap = app.state.snapshot()
                snap["prefix"] = app.prefix  # so the page can show `<prefix> sync`
                self._send(200, json.dumps(snap).encode(), "application/json")
            elif path == "/mem":
                # On-demand physical-memory read (used by the page-table tree).
                q = parse_qs(urlparse(self.path).query)
                try:
                    phys = int(q.get("phys", ["0"])[0], 16)
                    count = int(q.get("count", ["512"])[0])
                except ValueError:
                    self._send(400, b'{"ok":false,"error":"bad params"}',
                               "application/json")
                    return
                count = max(1, min(count, 512))
                self._send(200, json.dumps(_read_phys_qwords(phys, count)).encode(),
                           "application/json")
            elif path in app.routes:
                # App-specific dynamic endpoint (e.g. the slab viewer's reads).
                q = parse_qs(urlparse(self.path).query)
                try:
                    code, body, ctype = app.routes[path](app, q)
                except Exception as exc:  # noqa: BLE001 - report cleanly as JSON
                    code = 500
                    body = json.dumps({"ok": False, "error": "%s: %s"
                                       % (type(exc).__name__, exc)})
                    ctype = "application/json"
                self._send(code, body, ctype)
            else:
                self._send(404, b"not found", "text/plain; charset=utf-8")

    return _Handler


class Server:
    def __init__(self, prefix, default_port, label, html_path,
                 static=None, routes=None, sync_fn=None, sync_hint=None):
        self.prefix = prefix
        self.default_port = default_port
        self.label = label
        self.html_path = html_path          # the "/" page
        self.static = static or {}          # {url_path: file_path}
        self.routes = routes or {}          # {url_path: handler(app, query)->(code, body, ctype)}
        self.sync_fn = sync_fn              # called by `<prefix> sync` (on the main thread)
        self.sync_hint = sync_hint or "the current data"
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
        httpd.app = self
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
        print("[%s] run `%s sync` in gdb to push %s"
              % (self.prefix, self.prefix, self.sync_hint))
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

    def sync(self, args=None):
        if self.sync_fn:
            self.sync_fn(self, args or [])


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
            self._server.sync(tokens[1:])
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


def install_app(*, prefix, default_port, label, html_path,
                static=None, routes=None, sync_fn=None, sync_hint=None):
    """Create (or hot-reload) a web-app server, register its ``<prefix>`` and
    ``sync`` gdb commands, and auto-start it.

    Shared by the register views and the slab viewer so the HTTP server, the
    commands, host binding and the reload logic live in exactly one place. Apps
    differ only in their page (``html_path``), static files, dynamic ``routes``
    and their ``sync_fn`` (run on gdb's main thread by ``<prefix> sync``).
    """
    static = dict(static or {})
    static.setdefault("/regviz.css", _CSS_PATH)  # every app shares the theme
    attr = "_regviz_%s" % prefix
    prev = getattr(gdb, attr, None)
    if prev is not None and getattr(prev, "_version", 0) != _VERSION:
        try:
            prev.stop(quiet=True)
        except Exception:  # noqa: BLE001
            pass
        prev = None

    if prev is None:
        server = Server(prefix, default_port, label, html_path,
                        static=static, routes=routes, sync_fn=sync_fn, sync_hint=sync_hint)
        setattr(gdb, attr, server)
    else:
        server = prev  # reuse the running server, but refresh its config on re-source
        server.html_path = html_path
        server.static = static or {}
        server.routes = routes or {}
        server.sync_fn = sync_fn
        server.sync_hint = sync_hint or server.sync_hint

    _ControlCommand(server)
    if not server.running:
        server.start()
    return server


def _register_sync(server, args=None):
    """sync_fn for the register views: read each register (trying alternates) and
    store the hex values for the page."""
    regs = {}
    for name, expr in server.exprs:
        candidates = expr if isinstance(expr, (list, tuple)) else [expr]
        value = None
        for cand in candidates:
            value = _read_reg(cand)
            if value is not None:
                break
        regs[name] = None if value is None else "0x%x" % value
    server.state.set({"regs": regs})
    parts = ["%s=%s" % (n, v if v else "n/a") for n, v in regs.items()]
    print("[%s] synced: %s" % (server.prefix, "  ".join(parts)))
    if all(v is None for v in regs.values()):
        print("[%s] no registers were readable — attach to a live target "
              "(e.g. a QEMU gdb stub) before syncing" % server.prefix)


def install(*, prefix, default_port, directory, regs_js, exprs, label):
    """Register-view convenience wrapper over :func:`install_app`.

    directory / regs_js locate the arch's ``regs.js`` served at ``/regs.js``.
    """
    regs_path = Path(directory).resolve() / regs_js
    server = install_app(
        prefix=prefix, default_port=default_port, label=label,
        html_path=_HTML_PATH,
        static={"/regs.js": regs_path},
        sync_fn=_register_sync,
        sync_hint="the current register values",
    )
    server.exprs = exprs  # read by _register_sync
    return server
