"""Kernel virtual memory map (kvmmap) — a GDB plugin.

Walks the current CR3's 4-level page tables and coalesces contiguous mappings
with the same permissions into regions — a `vmmap` for the kernel, built purely
from memory: CR3 is a register and the page tables are read as physical memory
over the QEMU monitor (`monitor xp`), so no symbols or vmlinux are needed.

    (gdb) source kernel/kvmmap/kvmmap_viz.py
    (gdb) kvmmap sync

Targets x86-64 4-level paging. Shared server/command/reload machinery lives in
kernel/regviz_common.py.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import importlib  # noqa: E402
import regviz_common  # noqa: E402

importlib.reload(regviz_common)  # pick up edits to the shared module on re-source

import gdb  # noqa: E402  (provided by the gdb Python runtime)

_PHYS = 0x000FFFFFFFFFF000          # next-table / 4K frame base bits
_FRAME = {12: 0x000FFFFFFFFFF000,   # 4K  (PT)
          21: 0x000FFFFFFFE00000,   # 2M  (PD, PS=1)
          30: 0x000FFFFFC0000000}   # 1G  (PDPT, PS=1)
_SHIFT = {0: 39, 1: 30, 2: 21, 3: 12}  # bits covered by an entry at each level
_MAX_TABLES = 200000                    # runaway guard


def _read_phys(phys, count):
    """Read `count` little-endian qwords of physical memory via the QEMU monitor.

    Called from the sync command (gdb's main thread), so gdb.execute is used
    directly. Returns a list of ints (possibly short/empty on failure).
    """
    try:
        out = gdb.execute("monitor xp/%dgx 0x%x" % (count, phys), from_tty=False,
                          to_string=True) or ""
    except gdb.error:
        return []
    return [int(v, 16) for v in re.findall(r"0x([0-9a-fA-F]+)", out)[:count]]


def _canon(va):
    if (va >> 47) & 1:
        return va | (~((1 << 48) - 1) & 0xFFFFFFFFFFFFFFFF)
    return va & ((1 << 48) - 1)


def _region(va):
    """Coarse x86-64 region label for a kernel/user virtual address."""
    if va < 0x0000800000000000:
        return "user"
    if va >= 0xFFFFFFFFFF600000:
        return "vsyscall"
    if va >= 0xFFFFFFFFA0000000:
        return "modules"
    if va >= 0xFFFFFFFF80000000:
        return "kernel image"
    if va >= 0xFFFFEA0000000000:
        return "vmemmap"
    if va >= 0xFFFFC90000000000:
        return "vmalloc"
    if va >= 0xFFFF800000000000:
        return "direct map"
    return "kernel"


def _perms(flags):
    return "".join([
        "r",
        "w" if flags["rw"] else "-",
        "x" if not flags["nx"] else "-",
        "u" if flags["us"] else "s",
        "g" if flags["g"] else "-",
    ])


def _walk(cr3):
    """Return coalesced mappings from the page-table tree rooted at `cr3`."""
    leaves = []
    tables = [0]

    def rec(table_phys, level, va_prefix):
        if tables[0] >= _MAX_TABLES:
            return
        tables[0] += 1
        vals = _read_phys(table_phys, 512)
        shift = _SHIFT[level]
        for i, e in enumerate(vals):
            if not (e & 1):            # present?
                continue
            va = va_prefix | (i << shift)
            is_leaf = level == 3 or (level in (1, 2) and (e >> 7) & 1)
            if is_leaf:
                flags = {
                    "rw": bool((e >> 1) & 1), "us": bool((e >> 2) & 1),
                    "a": bool((e >> 5) & 1), "d": bool((e >> 6) & 1),
                    "g": bool((e >> 8) & 1), "nx": bool((e >> 63) & 1),
                }
                leaves.append((_canon(va), 1 << shift, e & _FRAME[shift], flags))
            else:
                rec(e & _PHYS, level + 1, va_prefix | (i << shift))

    rec(cr3 & _PHYS, 0, 0)
    leaves.sort(key=lambda m: m[0])

    # Coalesce adjacent leaves with contiguous VA + PA and identical permissions.
    ranges = []
    for va, size, phys, fl in leaves:
        key = (fl["rw"], fl["us"], fl["nx"], fl["g"])
        if ranges:
            pv, pend, pphys, pkey, _ = ranges[-1]
            if key == pkey and va == pend and phys == (pphys + (pend - pv)):
                ranges[-1] = (pv, va + size, pphys, pkey, fl)
                continue
        ranges.append((va, va + size, phys, key, fl))

    out = []
    for va, end, phys, _key, fl in ranges:
        out.append({
            "va": "0x%016x" % va,
            "va_end": "0x%016x" % end,
            "size": end - va,
            "phys": "0x%x" % phys,
            "perms": _perms(fl),
            "rw": fl["rw"], "us": fl["us"], "nx": fl["nx"], "g": fl["g"],
            "region": _region(va),
        })
    return out


def _kvmmap_sync(server, args=None):
    try:
        cr3 = int(gdb.parse_and_eval("$cr3")) & 0xFFFFFFFFFFFFFFFF
    except gdb.error as exc:
        server.state.set({"ranges": [], "error": "cannot read $cr3: %s" % exc})
        print("[kvmmap] cannot read $cr3 — attach to a live x86-64 target: %s" % exc)
        return
    ranges = _walk(cr3)
    if not ranges:
        server._kvmmap_groups = {}
        server.state.set({"groups": [], "cr3": "0x%x" % cr3,
                          "error": "no mappings read — is this a QEMU target "
                                   "(page tables are read over `monitor xp`)?"})
        print("[kvmmap] no mappings — need a QEMU target with a monitor")
        return

    # Group by permission string so the page shows a handful of collapsible
    # groups instead of one giant table; keep the per-group ranges on the server
    # and hand them out on demand (/kvmranges) when a group is expanded.
    groups = {}
    for r in ranges:
        groups.setdefault(r["perms"], []).append(r)
    server._kvmmap_groups = groups
    summary = sorted(
        ({"perms": p, "count": len(rs), "total": sum(x["size"] for x in rs)}
         for p, rs in groups.items()),
        key=lambda g: -g["total"])
    server.state.set({"groups": summary, "cr3": "0x%x" % cr3, "nregions": len(ranges)})
    print("[kvmmap] synced %d regions (%d perm groups) from CR3=0x%x"
          % (len(ranges), len(groups), cr3))


def _route_ranges(app, query):
    """Ranges of one permission group, on demand (keeps /data small)."""
    perms = query.get("perms", [""])[0]
    groups = getattr(app, "_kvmmap_groups", {}) or {}
    rs = groups.get(perms, [])
    cap = 5000
    body = {"ok": True, "perms": perms, "total": len(rs),
            "ranges": rs[:cap], "truncated": len(rs) > cap}
    return 200, json.dumps(body), "application/json"


regviz_common.install_app(
    prefix="kvmmap",
    default_port=8775,
    label="kernel memory-map",
    html_path=Path(__file__).resolve().parent / "kvmmap_viz.html",
    routes={"/kvmranges": _route_ranges},
    sync_fn=_kvmmap_sync,
    sync_hint="the kernel memory map (walks CR3)",
)
