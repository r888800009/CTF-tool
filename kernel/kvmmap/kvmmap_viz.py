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
import kmem  # noqa: E402

importlib.reload(regviz_common)  # pick up edits to the shared modules on re-source
importlib.reload(kmem)

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
    if va >= 0xFFFFFFFFFF000000:
        return "cpu_entry_area"
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

    # Linear run-length collapse of consecutive leaves that look the same:
    #  - "contig": VA and PA both continue → merge into one solid region;
    #  - "repeat": the same physical frame reappears at a regular VA stride
    #    (e.g. the vmemmap zero page) → collapse into one "N × page" entry.
    items = []
    cur = None
    for va, size, phys, fl in leaves:
        region = _region(va)
        key = (fl["rw"], fl["us"], fl["nx"], fl["g"], region)
        if cur is not None and cur["key"] == key and cur["page"] == size:
            if (va == cur["last_va"] + cur["page"] and phys == cur["last_phys"] + cur["page"]
                    and cur["kind"] in (None, "contig")):
                cur.update(kind="contig", count=cur["count"] + 1, last_va=va, last_phys=phys)
                continue
            if phys == cur["phys0"] and cur["kind"] in (None, "repeat"):
                stride = va - cur["last_va"]
                if stride > 0 and (cur["kind"] != "repeat" or stride == cur["stride"]):
                    cur.update(kind="repeat", stride=stride, count=cur["count"] + 1,
                               last_va=va, last_phys=phys)
                    continue
        cur = {"va0": va, "page": size, "phys0": phys, "key": key, "region": region,
               "count": 1, "last_va": va, "last_phys": phys, "kind": None, "stride": 0,
               "perms": _perms(fl)}
        items.append(cur)

    out = []
    for it in items:
        repeat = it["kind"] == "repeat"
        va_end = it["last_va"] + it["page"]
        out.append({
            "va": "0x%016x" % it["va0"],
            "va_end": "0x%016x" % va_end,
            "phys": "0x%x" % it["phys0"],
            "perms": it["perms"],
            "region": it["region"],
            "repeat": repeat,
            "count": it["count"],
            "page": it["page"],
            "stride": it["stride"],
            "size": it["count"] * it["page"] if repeat else va_end - it["va0"],
            "module": "",
        })
    return out


# ---- Best-effort module-name resolution (pure memory) ---------------------
_MOD_MIN, _MOD_MAX = 0xFFFFFFFFC0000000, 0xFFFFFFFFFEFFFFFF
_MOD_IMG_RANGE = 96 * 1024 * 1024
_MODS_CACHE = None   # sorted [(base, name)]


def _is_mod(v):
    return _MOD_MIN <= v <= _MOD_MAX


def _name_in(win, dn):
    end = win.find(b"\x00", dn)
    if end < 0 or end == dn or not (2 <= end - dn <= 55):
        return None
    s = win[dn:end]
    # strict ASCII [0-9A-Za-z_.-] only (byte checks; chr().isalnum() is Unicode-aware
    # and would accept high bytes, then decode to replacement chars)
    if all(48 <= c <= 57 or 65 <= c <= 90 or 97 <= c <= 122 or c in (0x5F, 0x2E, 0x2D)
           for c in s):
        return s.decode("ascii")
    return None


def _mod_ptrs(win, ps):
    out = []
    for o in range(0, len(win) - ps, ps):
        v = int.from_bytes(win[o:o + ps], "little")
        if _is_mod(v):
            out.append(v)
    return out


def _discover_modules():
    """Find the kernel `modules` list by scanning and return sorted (base, name).

    Best-effort and needs kernel context (reads `struct module` by VA). Returns []
    when it can't (userspace/KPTI, or the layout is not recognised) — names blank.
    """
    ps = kmem.ptr_size()
    anchor = kmem.text_anchor()
    if anchor is None:
        return []
    image_start = anchor & ~0x1FFFFF
    buf = kmem.read_image(image_start, _MOD_IMG_RANGE)
    if not buf:
        return []

    # Find the modules list head: a .data list_head whose next `struct module`
    # has a printable module name at a consistent inline offset and points into
    # the module area, and whose ring's next node matches the same name offset.
    head = name_delta = None
    checked = 0
    for off in range(0, len(buf) - 2 * ps, ps):
        nxt = int.from_bytes(buf[off:off + ps], "little")
        prv = int.from_bytes(buf[off + ps:off + 2 * ps], "little")
        if not (kmem.is_kheap(nxt) and kmem.is_kheap(prv) and nxt != prv):
            continue
        checked += 1
        if checked > 4000:
            break
        try:
            win = kmem.read_mem(nxt, 320)
        except gdb.error:
            continue
        if not _mod_ptrs(win, ps):
            continue
        for dn in range(ps, 200):
            if not _name_in(win, dn):
                continue
            nn = int.from_bytes(win[0:ps], "little")
            try:
                if _name_in(kmem.read_mem(nn, dn + 56), dn):
                    head, name_delta = image_start + off, dn
                    break
            except gdb.error:
                pass
        if head is not None:
            break
    if head is None:
        return []

    mods = []
    seen = set()
    node = kmem.rd_ptr_safe(head)
    while node and node != head and node not in seen and len(seen) < 4096:
        seen.add(node)
        try:
            name = _name_in(kmem.read_mem(node, name_delta + 56), name_delta)
            around = kmem.read_mem(node - 128, 640)
        except gdb.error:
            break
        if name:
            for b in set(_mod_ptrs(around, ps)):
                mods.append((b, name))
        node = kmem.rd_ptr_safe(node)
    mods.sort()
    return mods


def _kvmmap_sync(server, args=None):
    try:
        cr3 = int(gdb.parse_and_eval("$cr3")) & 0xFFFFFFFFFFFFFFFF
    except gdb.error as exc:
        server.state.set({"ranges": [], "error": "cannot read $cr3: %s" % exc})
        print("[kvmmap] cannot read $cr3 — attach to a live x86-64 target: %s" % exc)
        return
    items = _walk(cr3)
    if not items:
        server._kvmmap_items = []
        server.state.set({"count": 0, "cr3": "0x%x" % cr3,
                          "error": "no mappings read — is this a QEMU target "
                                   "(page tables are read over `monitor xp`)?"})
        print("[kvmmap] no mappings — need a QEMU target with a monitor")
        return

    # Best-effort: label modules-region rows with their owning module name.
    global _MODS_CACHE
    if any(it["region"] == "modules" for it in items):
        if _MODS_CACHE is None:
            _MODS_CACHE = _discover_modules()
        mods = _MODS_CACHE
        if mods:
            import bisect
            bases = [m[0] for m in mods]
            for it in items:
                if it["region"] == "modules":
                    i = bisect.bisect_right(bases, int(it["va"], 16)) - 1
                    it["module"] = mods[i][1] if i >= 0 else ""

    # Keep the (already run-length-collapsed) list on the server; the 1s poll only
    # carries a small summary and the page fetches the list once per sync.
    server._kvmmap_items = items
    server.state.set({"count": len(items), "cr3": "0x%x" % cr3})
    print("[kvmmap] synced %d entries from CR3=0x%x" % (len(items), cr3))


def _route_list(app, query):
    """The full run-length-collapsed map, fetched once per sync (keeps /data small)."""
    items = getattr(app, "_kvmmap_items", []) or []
    cap = 20000
    return 200, json.dumps({"ok": True, "total": len(items), "items": items[:cap],
                            "truncated": len(items) > cap}), "application/json"


regviz_common.install_app(
    prefix="kvmmap",
    default_port=8775,
    label="kernel memory-map",
    html_path=Path(__file__).resolve().parent / "kvmmap_viz.html",
    routes={"/kvmlist": _route_list},
    sync_fn=_kvmmap_sync,
    sync_hint="the kernel memory map (walks CR3)",
)
