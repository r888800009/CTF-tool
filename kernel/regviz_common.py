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
import socketserver
import threading
import time
import webbrowser
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# ``ThreadingHTTPServer`` was added in Python 3.7.  Keep the visualizers
# usable with older Python runtimes embedded in GDB.
if not hasattr(http.server, "ThreadingHTTPServer"):
    class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

    http.server.ThreadingHTTPServer = ThreadingHTTPServer

import gdb  # provided by the gdb Python runtime

_VERSION = 12  # bump when this shared implementation changes so re-sourcing hot-reloads
_HTML_PATH = Path(__file__).resolve().parent / "regviz.html"
_CSS_PATH = Path(__file__).resolve().parent / "regviz.css"  # shared theme for every app
_HEXVIEW_PATH = Path(__file__).resolve().parent / "hexview.js"  # shared hexdump helper
_NAV_PATH = Path(__file__).resolve().parent / "nav.js"  # shared cross-module nav bar

# All viewers share ONE HTTP server (the "hub") on one port. Each registers an App
# under its prefix; pages are served at /<prefix>/ and their relative fetches
# (data, regs.js, …) resolve there via an injected <base>, while these resources
# are global across every tool. Re-sourcing one plugin only replaces its registry
# entry — the hub keeps running, so the other tools are never interrupted.
_HUB_DEFAULT_PORT = 8780
_GLOBAL_STATIC = {               # url -> file, served the same for every app
    "/regviz.css": _CSS_PATH,
    "/hexview.js": _HEXVIEW_PATH,
    "/nav.js": _NAV_PATH,
}
# Root paths handled by the hub itself (never routed to an app prefix).
_GLOBAL_ENDPOINTS = frozenset({"/nav", "/mem", "/read", "/disas", "/kinfo", "/vaperm"})


def _apps():
    """The process-wide {prefix: App} registry (one dict for the whole gdb)."""
    reg = getattr(gdb, "_regviz_apps", None)
    if reg is None:
        reg = {}
        gdb._regviz_apps = reg
    return reg


def _running_apps():
    """Every registered viewer, for the cross-module navigation bar. They all share
    one hub on one port now, so each entry links by path: {prefix, label}. Sorted
    by prefix for a stable bar."""
    apps = [{"prefix": p, "label": a.label} for p, a in _apps().items()]
    apps.sort(key=lambda a: a["prefix"])
    return apps


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


def _kernel_image_extent():
    """Best-effort VA extent of the kernel image, read from memory (no symbols).

    The image is the contiguous mapped run around the kernel text anchor ($pc if it
    is in kernel text, else a kernel return address on the stack), probed at 2 MiB
    granularity. This lets the browser colour kernel-text vs module pointers
    correctly even when KASLR relocates the image above the classic fixed split
    (symbols are no help: the loaded vmlinux isn't KASLR-adjusted). Returns
    {"img": ["0xlo", "0xhi"]} or {"img": None}.
    """
    KLO, KHI, STEP = 0xFFFFFFFF80000000, 0xFFFFFFFFFF000000, 0x200000
    inf = gdb.selected_inferior()

    def mapped(va):
        try:
            inf.read_memory(va, 1)
            return True
        except gdb.error:
            return False

    anchor = None
    try:
        pc = int(gdb.parse_and_eval("$pc")) & 0xFFFFFFFFFFFFFFFF
        if KLO <= pc < 0xFFFFFFFFFFFFFFFF:
            anchor = pc
    except gdb.error:
        pass
    if anchor is None:
        try:
            sp = int(gdb.parse_and_eval("$sp")) & 0xFFFFFFFFFFFFFFFF
            blob = bytes(inf.read_memory(sp, 64 * 1024))
            for i in range(0, len(blob) - 8, 8):
                v = int.from_bytes(blob[i:i + 8], "little")
                if KLO <= v < KHI:
                    anchor = v
                    break
        except gdb.error:
            pass
    if anchor is None or not (KLO <= anchor < KHI):
        return {"img": None}
    base = anchor & ~(STEP - 1)
    lo = base
    while lo - STEP >= KLO and mapped(lo - STEP):
        lo -= STEP
    hi = base + STEP
    while hi < KHI and mapped(hi):
        hi += STEP
    return {"img": ["0x%x" % lo, "0x%x" % hi]}


def _read_qword_phys(phys):
    """One little-endian qword at physical `phys` via the monitor, or None.

    Runs on gdb's main thread (called from within call_on_main), so it uses
    gdb.execute directly rather than posting another main-thread task.
    """
    try:
        out = gdb.execute("monitor xp/1gx 0x%x" % phys, from_tty=False, to_string=True) or ""
    except gdb.error:
        return None
    m = re.findall(r"0x([0-9a-fA-F]+)", out)
    return int(m[-1], 16) if m else None   # last 0x token is the value (addr prefix has none)


def _va_perms(va):
    """Permissions of VA `va` in the current CR3 — a single-address page walk, no
    symbols. Lets the browser pick asm (executable) vs hex (data) for an address.
    Returns {present, x, w, user, size} or {present: False}.
    """
    PHYS = 0x000FFFFFFFFFF000
    try:
        cr3 = int(gdb.parse_and_eval("$cr3")) & 0xFFFFFFFFFFFFFFFF
        cr4 = int(gdb.parse_and_eval("$cr4")) & 0xFFFFFFFFFFFFFFFF
    except gdb.error:
        return {"present": False, "error": "no cr3/cr4 (not a live target?)"}
    levels = 5 if (cr4 >> 12) & 1 else 4          # CR4.LA57
    shifts = [12 + 9 * (levels - 1 - lv) for lv in range(levels)]
    table = cr3 & PHYS
    rw = us = True
    nx = False
    for lv in range(levels):
        shift = shifts[lv]
        ent = _read_qword_phys(table + ((va >> shift) & 0x1FF) * 8)
        if ent is None or not (ent & 1):
            return {"present": False}
        rw = rw and bool((ent >> 1) & 1)          # effective perms AND down the walk
        us = us and bool((ent >> 2) & 1)
        nx = nx or bool((ent >> 63) & 1)
        if lv == levels - 1 or (shift in (21, 30) and (ent >> 7) & 1):   # leaf
            return {"present": True, "x": not nx, "w": rw, "user": us, "size": 1 << shift}
        table = ent & PHYS
    return {"present": False}


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

        def _send_page(self, app):
            """Serve an app's HTML with a ``<base href="/<prefix>/">`` (so the page's
            relative fetches — data, regs.js, the app's own routes — resolve under
            its prefix while /regviz.css, /hexview.js and the shared endpoints stay
            global) plus the cross-module nav bar, injected without editing the HTML.
            """
            try:
                html = Path(app.html_path).read_text()
            except OSError as exc:
                self._send(500, str(exc), "text/plain; charset=utf-8")
                return
            base = '<base href="/%s/">' % app.prefix
            i = html.lower().find("<head>")
            if i != -1 and base not in html:
                html = html[:i + 6] + "\n  " + base + html[i + 6:]
            nav = '<script src="/nav.js"></script>'
            if nav not in html:
                html = (html.replace("</body>", nav + "\n</body>", 1)
                        if "</body>" in html else html + "\n" + nav)
            self._send(200, html, "text/html; charset=utf-8")

        def _send_landing(self):
            """The hub root: a small index linking to every registered viewer."""
            items = "".join(
                '<li><a href="/%s/">%s</a> <span class="sub">%s</span></li>'
                % (a["prefix"], a["prefix"], a["label"]) for a in _running_apps()
            ) or "<li class='sub'>尚無已載入的工具（在 gdb source 其中一個 viewer）</li>"
            html = ("<!doctype html><html lang=zh-Hant><head><meta charset=utf-8>"
                    "<title>Kernel viewers</title><link rel=stylesheet href=\"/regviz.css\">"
                    "</head><body><h1>Kernel viewers</h1>"
                    "<ul style='line-height:2;list-style:none;padding:0'>" + items + "</ul>"
                    '<script src="/nav.js"></script></body></html>')
            self._send(200, html, "text/html; charset=utf-8")

        def _global_endpoint(self, path):
            q = parse_qs(urlparse(self.path).query)
            if path == "/nav":
                self._send(200, json.dumps({"apps": _running_apps()}).encode(),
                           "application/json"); return
            if path == "/mem":
                try:
                    phys = int(q.get("phys", ["0"])[0], 16)
                    count = max(1, min(int(q.get("count", ["512"])[0]), 512))
                except ValueError:
                    self._send(400, b'{"ok":false,"error":"bad params"}', "application/json"); return
                self._send(200, json.dumps(_read_phys_qwords(phys, count)).encode(),
                           "application/json"); return
            if path == "/read":
                try:
                    addr = int(q.get("addr", ["0"])[0], 16)
                    count = max(1, min(int(q.get("count", ["256"])[0]), 8192))
                except ValueError:
                    self._send(400, b'{"ok":false,"error":"bad params"}', "application/json"); return
                res = call_on_main(lambda: bytes(gdb.selected_inferior().read_memory(addr, count)))
                body = ({"ok": True, "addr": "0x%x" % addr, "hex": res["result"].hex()}
                        if res.get("ok") else {"ok": False, "error": res.get("error", "read failed")})
                self._send(200, json.dumps(body).encode(), "application/json"); return
            if path == "/disas":
                try:
                    addr = int(q.get("addr", ["0"])[0], 16)
                    count = max(1, min(int(q.get("count", ["24"])[0]), 256))
                except ValueError:
                    self._send(400, b'{"ok":false,"error":"bad params"}', "application/json"); return
                res = _run_on_main("x/%di 0x%x" % (count, addr))
                body = ({"ok": True, "addr": "0x%x" % addr, "text": res.get("output", "")}
                        if res.get("ok") else {"ok": False, "error": res.get("error", "disassembly failed")})
                self._send(200, json.dumps(body).encode(), "application/json"); return
            if path == "/kinfo":
                res = call_on_main(_kernel_image_extent)
                body = dict(res["result"]) if res.get("ok") else {"error": res.get("error", "kinfo failed")}
                body["ok"] = bool(res.get("ok"))
                self._send(200, json.dumps(body).encode(), "application/json"); return
            if path == "/vaperm":
                try:
                    addr = int(q.get("addr", ["0"])[0], 16)
                except ValueError:
                    self._send(400, b'{"ok":false,"error":"bad params"}', "application/json"); return
                res = call_on_main(lambda: _va_perms(addr))
                body = dict(res["result"]) if res.get("ok") else {"error": res.get("error", "vaperm failed")}
                body["ok"] = bool(res.get("ok"))
                self._send(200, json.dumps(body).encode(), "application/json"); return
            self._send(404, b"not found", "text/plain; charset=utf-8")

        def do_GET(self):
            raw = self.path.split("?", 1)[0]
            if raw in _GLOBAL_STATIC:                       # shared files, same for all
                self._send_file(_GLOBAL_STATIC[raw], _ctype_for(raw)); return
            if raw in _GLOBAL_ENDPOINTS:                    # shared JSON endpoints
                self._global_endpoint(raw); return
            if raw in ("/", "/index.html"):                # hub landing page
                self._send_landing(); return
            seg = raw.strip("/").split("/", 1)             # /<prefix>/<rest>
            app = _apps().get(seg[0])
            rest = "/" + (seg[1] if len(seg) > 1 else "")
            if app is None:
                self._send(404, b"not found", "text/plain; charset=utf-8"); return
            if rest == "/":
                self._send_page(app); return
            if rest == "/data":
                snap = app.state.snapshot(); snap["prefix"] = app.prefix
                self._send(200, json.dumps(snap).encode(), "application/json"); return
            if rest in app.static:
                self._send_file(app.static[rest], _ctype_for(rest)); return
            if rest in app.routes:
                q = parse_qs(urlparse(self.path).query)
                try:
                    code, body, ctype = app.routes[rest](app, q)
                except Exception as exc:  # noqa: BLE001 - report cleanly as JSON
                    code = 500
                    body = json.dumps({"ok": False, "error": "%s: %s"
                                       % (type(exc).__name__, exc)})
                    ctype = "application/json"
                self._send(code, body, ctype); return
            self._send(404, b"not found", "text/plain; charset=utf-8")

    return _Handler


class App:
    """One viewer registered with the hub: its page, per-app static files, dynamic
    routes and sync function. Holds no socket — the hub serves it under /<prefix>/.
    """

    def __init__(self, prefix, label, html_path, static, routes, sync_fn, sync_hint):
        self.prefix = prefix
        self.label = label
        self.html_path = html_path          # served at /<prefix>/
        self.static = static or {}          # {"/regs.js": file, ...} under /<prefix>/
        self.routes = routes or {}          # {"/kvmlist": handler(app, query)->(code,body,ctype)}
        self.sync_fn = sync_fn              # run on gdb's main thread by `<prefix> sync`
        self.sync_hint = sync_hint or "the current data"
        self.state = _State()

    def sync(self, args=None):
        if self.sync_fn:
            self.sync_fn(self, args or [])


class Hub:
    """The single shared HTTP server. One socket, one port; it routes every
    registered App by the first path segment and serves the global resources."""

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self._httpd = None
        self._thread = None
        self._version = _VERSION

    @property
    def running(self):
        return self._httpd is not None

    def url(self, prefix=""):
        host = _primary_ip() if self.host in ("0.0.0.0", "::") else self.host
        return "http://%s:%d/%s" % (host, self.port, (prefix + "/") if prefix else "")

    def start(self):
        if self._httpd is not None:
            return True
        try:
            httpd = http.server.ThreadingHTTPServer((self.host, self.port), _make_handler())
        except OSError as exc:
            print("[regviz] could not bind %s:%d — %s" % (self.host, self.port, exc))
            return False
        self._httpd = httpd
        self._thread = threading.Thread(target=httpd.serve_forever,
                                        name="regviz-hub", daemon=True)
        self._thread.start()
        print("[regviz] hub serving at %s" % self.url())
        if self.host not in ("127.0.0.1", "localhost", "::1"):
            print("[regviz] bound to %s — reachable from other machines" % self.host)
        return True

    def stop(self, quiet=False):
        if self._httpd is None:
            return
        self._httpd.shutdown()
        self._httpd.server_close()
        self._httpd = None
        self._thread = None
        if not quiet:
            print("[regviz] hub stopped")


def _sweep_legacy_servers():
    """Stop any per-app servers left by an older (pre-hub) version in this gdb."""
    for name in list(vars(gdb)):
        if not name.startswith("_regviz_") or name in ("_regviz_hub", "_regviz_apps"):
            continue
        obj = getattr(gdb, name, None)
        if getattr(obj, "_httpd", None) is not None and hasattr(obj, "stop"):
            try:
                obj.stop(quiet=True)
            except Exception:  # noqa: BLE001
                pass
        try:
            delattr(gdb, name)
        except Exception:  # noqa: BLE001
            pass


def _ensure_hub(host=None, port=None, rebind=False):
    """Return the running hub, starting it the first time. A version bump (shared
    code changed) or an explicit rebind restarts it; a plain plugin re-source does
    not touch it, so the other tools keep serving without interruption."""
    hub = getattr(gdb, "_regviz_hub", None)
    keep_host = keep_port = None
    if hub is not None and hub._version != _VERSION:
        keep_host, keep_port = hub.host, hub.port   # carry the bind across a version restart
        hub.stop(quiet=True)
        hub = None
    if hub is None:
        _sweep_legacy_servers()
        hub = Hub(host or keep_host or "127.0.0.1", port or keep_port or _HUB_DEFAULT_PORT)
        gdb._regviz_hub = hub
    elif rebind and (host is not None or port is not None):
        if host is not None:
            hub.host = host
        if port is not None:
            hub.port = port
        hub.stop(quiet=True)
    if not hub.running:
        hub.start()
    return hub


class _ControlCommand(gdb.Command):
    """Control a viewer.  Usage: <prefix> [start [HOST] [PORT] | sync | stop | status]

    All viewers share one hub on one port; `<prefix> start` opens that viewer's
    page (and, with HOST/PORT, rebinds the shared hub — HOST 0.0.0.0 listens on
    every interface for another machine). `<prefix> sync` pushes fresh data.
    """

    def __init__(self, app):
        super().__init__(app.prefix, gdb.COMMAND_USER)
        self._prefix = app.prefix

    def invoke(self, arg, from_tty):
        app = _apps().get(self._prefix)
        hub = getattr(gdb, "_regviz_hub", None)
        if app is None:
            print("[%s] not registered — re-source its plugin" % self._prefix)
            return
        tokens = gdb.string_to_argv(arg)
        if not tokens or tokens[0] == "status":
            if hub is None or not hub.running:
                print("[%s] hub not running — `%s start` or `%s sync`"
                      % (self._prefix, self._prefix, self._prefix))
                return
            snap = app.state.snapshot()
            when = "never" if not snap["synced"] else time.strftime(
                "%H:%M:%S", time.localtime(snap["synced_at"]))
            print("[%s] %s (last sync: %s)" % (self._prefix, hub.url(self._prefix), when))
            return
        sub = tokens[0]
        if sub == "sync":
            _ensure_hub()
            app.sync(tokens[1:])
            return
        if sub == "stop":
            _apps().pop(self._prefix, None)
            print("[%s] unregistered from the hub" % self._prefix)
            if not _apps() and hub is not None:
                hub.stop()
            return
        if sub in ("start", "restart"):
            rest = tokens[1:]
        elif sub.isdigit() or ":" in sub or _looks_like_host(sub):
            rest = tokens  # `<prefix> 8000` / `<prefix> 0.0.0.0` shorthand
        else:
            print("usage: %s [start [HOST] [PORT] | sync | stop | status]" % self._prefix)
            return
        host, port = _parse_host_port(rest)
        hub = _ensure_hub(host=host, port=port, rebind=True)
        if hub.running:
            url = hub.url(self._prefix)
            print("[%s] open %s" % (self._prefix, url))
            try:
                webbrowser.open(url)
            except Exception:  # noqa: BLE001 - headless boxes have no browser
                pass


class _HubCommand(gdb.Command):
    """Control the shared viewer hub (all tools live on one port).

    Usage: regviz [status | bind [HOST] [PORT] | stop | open [PREFIX]]

    `regviz bind 0.0.0.0 9000` moves every tool to that address/port in one step —
    independent of any single viewer, so it works even after a `<viz> stop`. HOST
    0.0.0.0 listens on every interface (for a browser on another machine); the
    default is loopback only.
    """

    def __init__(self):
        super().__init__("regviz", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        tokens = gdb.string_to_argv(arg)
        hub = getattr(gdb, "_regviz_hub", None)
        if not tokens or tokens[0] == "status":
            if hub is None or not hub.running:
                print("[regviz] hub not running (source a viewer, or `regviz bind`)")
            else:
                print("[regviz] hub at %s (bind %s:%d)" % (hub.url(), hub.host, hub.port))
            for a in _running_apps():
                print("  %s%s  (%s)" % (hub.url(a["prefix"]) if hub and hub.running
                                        else "/%s/" % a["prefix"], "", a["label"]))
            return
        sub = tokens[0]
        if sub == "stop":
            if hub is not None and hub.running:
                hub.stop()
            else:
                print("[regviz] hub not running")
            return
        if sub == "open":
            hub = _ensure_hub()
            url = hub.url(tokens[1] if len(tokens) > 1 else "")
            print("[regviz] open %s" % url)
            try:
                webbrowser.open(url)
            except Exception:  # noqa: BLE001
                pass
            return
        if sub in ("bind", "start", "restart"):
            rest = tokens[1:]
        elif sub.isdigit() or ":" in sub or _looks_like_host(sub):
            rest = tokens  # `regviz 9000` / `regviz 0.0.0.0` shorthand
        else:
            print("usage: regviz [status | bind [HOST] [PORT] | stop | open [PREFIX]]")
            return
        host, port = _parse_host_port(rest)
        hub = _ensure_hub(host=host, port=port, rebind=True)
        if hub.running:
            print("[regviz] hub now at %s (bind %s:%d)" % (hub.url(), hub.host, hub.port))


def install_app(*, prefix, default_port=None, label, html_path,
                static=None, routes=None, sync_fn=None, sync_hint=None):
    """Register (or hot-replace) a viewer on the shared hub and define its
    ``<prefix>`` gdb command. Re-sourcing only swaps this app's registry entry —
    the hub (and every other tool) keeps running, so there is no reload stall.
    ``default_port`` is accepted for backward compatibility but ignored: all tools
    share the hub's single port.
    """
    apps = _apps()
    app = App(prefix, label, html_path, static or {}, routes or {}, sync_fn, sync_hint)
    prev = apps.get(prefix)
    if prev is not None:
        app.state = prev.state                 # keep the last sync across a re-source
        if hasattr(prev, "exprs"):
            app.exprs = prev.exprs
    apps[prefix] = app
    _ControlCommand(app)
    _HubCommand()               # (re)register the viewer-independent `regviz` command
    hub = _ensure_hub()
    if hub.running:
        print("[%s] ready at %s" % (prefix, hub.url(prefix)))
    return app


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
