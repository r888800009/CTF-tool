"""Kernel virtual memory map (kvmmap) — a GDB plugin.

Walks the current CR3's 4-level page tables and coalesces contiguous mappings
with the same permissions into regions — a `vmmap` for the kernel, built purely
from memory: CR3 is a register and the page tables are read as physical memory
over the QEMU monitor (`monitor xp`), so no symbols or vmlinux are needed.

    (gdb) source kernel/kvmmap/kvmmap_viz.py
    (gdb) kvmmap sync

Targets x86-64 long mode and auto-detects the paging depth: 4-level, or 5-level
(LA57) as used by many syzkaller/syzbot kernels. The depth is taken from CR4.LA57
and confirmed by whether the walk recovers the kernel-text mapping, so it adapts
across kernel versions and configs rather than assuming one layout. Shared
server/command/reload machinery lives in kernel/regviz_common.py.
"""

import json
import re
import struct
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
_MAX_TABLES = 200000                    # runaway guard


def _level_shifts(levels):
    """Map each level index (0 = top table) to the VA bit it indexes.

    4-level: {0: 39, 1: 30, 2: 21, 3: 12} (PML4→PDPT→PD→PT).
    5-level: prepends a PML5 at bit 48 → {0: 48, 1: 39, 2: 30, 3: 21, 4: 12}.
    """
    return {lv: 12 + 9 * (levels - 1 - lv) for lv in range(levels)}


def _va_bits(levels):
    """Canonical virtual-address width: 48 bits (4-level) or 57 bits (5-level)."""
    return 48 if levels <= 4 else 57


# Kernel direct-map base (page_offset_base). When known, physical memory is
# readable as ordinary guest memory at `base + phys`, which lets us pull page
# tables over the fast binary gdb memory protocol instead of the `monitor xp`
# text command — ~10x fewer milliseconds per table, the difference between a
# multi-second sync and a ~30s one on kernels whose direct map is split to 4 KiB
# pages (debug_pagealloc / KASAN, common on syzkaller). None = fall back to xp.
_POB = None


def _read_phys_monitor(phys, count):
    """Read `count` little-endian qwords of physical memory via the QEMU monitor.

    The portable path: works on any QEMU target with a monitor, no direct map
    needed. Returns a list of ints (possibly short/empty on failure).
    """
    try:
        out = gdb.execute("monitor xp/%dgx 0x%x" % (count, phys), from_tty=False,
                          to_string=True) or ""
    except gdb.error:
        return []
    return [int(v, 16) for v in re.findall(r"0x([0-9a-fA-F]+)", out)[:count]]


def _read_phys(phys, count):
    """Read `count` little-endian qwords of physical memory.

    Fast path through the direct map when `_POB` is known (binary read_memory);
    otherwise, or on any fault, the `monitor xp` fallback. Called from the sync
    command on gdb's main thread. Returns a list of ints.
    """
    if _POB is not None:
        try:
            raw = bytes(gdb.selected_inferior().read_memory(_POB + phys, count * 8))
            return list(struct.unpack("<%dQ" % count, raw))
        except (gdb.error, struct.error):
            pass   # page not in the direct map (or no inferior) — fall back
    return _read_phys_monitor(phys, count)


def _canon(va, bits):
    """Sign-extend `va` from the canonical boundary (bit 47 for 4-level / 56 for
    5-level) the way the CPU does, so high-half kernel addresses come out right."""
    if (va >> (bits - 1)) & 1:
        return va | (~((1 << bits) - 1) & 0xFFFFFFFFFFFFFFFF)
    return va & ((1 << bits) - 1)


# Kernel address-space layout. The top of the space (kernel text / modules /
# vsyscall / fixmap / cpu_entry_area) sits at the same addresses in both modes;
# only the petabyte-scale direct map, vmalloc and vmemmap windows (and the
# user/kernel split) move when 5-level paging widens the address space. The
# window *starts* are catch-all lower bounds so the labels survive KASLR of the
# per-window base. See Documentation/x86/x86_64/mm.rst.
_LAYOUT = {
    4: {"user_end":   0x0000800000000000,
        "direct_map": 0xFFFF800000000000,
        "vmalloc":    0xFFFFC90000000000,
        "vmemmap":    0xFFFFEA0000000000},
    5: {"user_end":   0x0100000000000000,
        "direct_map": 0xFF00000000000000,
        "vmalloc":    0xFFA0000000000000,
        "vmemmap":    0xFFD4000000000000},
}


def _region(va, levels, img=(None, None)):
    """Coarse x86-64 region label for a kernel/user virtual address, chosen for
    the active paging mode (4- vs 5-level move the big mid-space windows).

    `img` is the measured kernel-image VA extent (lo, hi); when known it, not a
    fixed boundary, separates "kernel image" from "modules" — KASLR relocates the
    image anywhere in [__START_KERNEL_map, MODULES_END), so the fixed
    0xffffffffa0000000 split mislabels a relocated image as modules. When unknown
    (no kernel context), fall back to the classic fixed thresholds.
    """
    lay = _LAYOUT[5 if levels >= 5 else 4]
    if va < lay["user_end"]:
        return "user"
    # top of the address space — identical under 4- and 5-level paging
    if va >= 0xFFFFFFFFFF600000:
        return "vsyscall"
    if va >= 0xFFFFFFFFFF000000:
        return "cpu_entry_area"   # fixmap / cpu_entry_area at the very top
    img_lo, img_hi = img
    if va >= 0xFFFFFFFF80000000:   # [__START_KERNEL_map, MODULES_END): image+modules
        if img_lo is not None:
            return "kernel image" if img_lo <= va < img_hi else "modules"
        # no measured extent: classic fixed split (correct only without KASLR)
        return "modules" if va >= 0xFFFFFFFFA0000000 else "kernel image"
    if 0xFFFFFE0000000000 <= va < 0xFFFFFE8000000000:
        return "cpu_entry_area"   # CPU_ENTRY_AREA_BASE (its own slot since ~4.16)
    # mode-dependent mid-space windows
    if va >= lay["vmemmap"]:
        return "vmemmap"
    if va >= lay["vmalloc"]:
        return "vmalloc"
    if va >= lay["direct_map"]:
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


def _kernel_image_span(leaves):
    """Measured VA extent of the kernel image: the contiguous mapped run (no VA
    gap) that contains the kernel text anchor ($pc, or a return address on the
    stack). KASLR relocates this run anywhere in [__START_KERNEL_map, MODULES_END),
    so reading it from the mapping beats assuming a fixed image/modules boundary.
    Returns (lo, hi), or (None, None) with no kernel context. `leaves` is sorted.
    """
    try:
        anchor = kmem.text_anchor()
    except Exception:  # noqa: BLE001
        anchor = None
    if anchor is None or not (0xFFFFFFFF80000000 <= anchor < 0xFFFFFFFFFF000000):
        return None, None
    run_lo = run_hi = None
    for va, size, _phys, _fl in leaves:
        if not (0xFFFFFFFF80000000 <= va < 0xFFFFFFFFFF000000):
            continue
        if run_lo is None or va != run_hi:        # start of a new contiguous run
            if run_lo is not None and run_lo <= anchor < run_hi:
                return run_lo, run_hi
            run_lo = va
        run_hi = va + size
    if run_lo is not None and run_lo <= anchor < run_hi:
        return run_lo, run_hi
    return None, None


def _walk(cr3, levels):
    """Return coalesced mappings from the `levels`-deep page-table tree at `cr3`.

    `levels` is 4 (PML4 root) or 5 (PML5 root, LA57). A leaf is the bottom level,
    or a PS=1 entry at the 2M/1G levels; the top levels never carry a PS leaf.
    """
    leaves = []
    tables = [0]
    shifts = _level_shifts(levels)
    bits = _va_bits(levels)

    def rec(table_phys, level, va_prefix):
        if tables[0] >= _MAX_TABLES:
            return
        tables[0] += 1
        vals = _read_phys(table_phys, 512)
        shift = shifts[level]
        for i, e in enumerate(vals):
            if not (e & 1):            # present?
                continue
            va = va_prefix | (i << shift)
            is_leaf = level == levels - 1 or (shift in (21, 30) and (e >> 7) & 1)
            if is_leaf:
                flags = {
                    "rw": bool((e >> 1) & 1), "us": bool((e >> 2) & 1),
                    "a": bool((e >> 5) & 1), "d": bool((e >> 6) & 1),
                    "g": bool((e >> 8) & 1), "nx": bool((e >> 63) & 1),
                }
                leaves.append((_canon(va, bits), 1 << shift, e & _FRAME[shift], flags))
            else:
                rec(e & _PHYS, level + 1, va)

    rec(cr3 & _PHYS, 0, 0)
    leaves.sort(key=lambda m: m[0])
    img = _kernel_image_span(leaves)   # KASLR-aware kernel-image vs modules split

    # Linear run-length collapse of consecutive leaves that look the same:
    #  - "contig": VA and PA both continue → merge into one solid region;
    #  - "repeat": the same physical frame reappears at a regular VA stride
    #    (e.g. the vmemmap zero page) → collapse into one "N × page" entry.
    items = []
    cur = None
    for va, size, phys, fl in leaves:
        region = _region(va, levels, img)
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


def _discover_modules(mod_ranges):
    """Find the kernel `modules` list by scanning and return sorted (base, name).

    `mod_ranges` is the list of actually-mapped module VA ranges (from the CR3
    walk); a candidate is only accepted when a `struct module` base falls inside
    one, which rejects other .data lists that happen to hold module-area pointers.
    Best-effort and needs kernel context (reads `struct module` by VA). Returns []
    when it can't (userspace/KPTI, or the layout is not recognised).
    """
    def in_r(v):
        return any(lo <= v < hi for lo, hi in mod_ranges)

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
        # both point into the kernel heap (a single-module list has next == prev)
        if not (kmem.is_kheap(nxt) and kmem.is_kheap(prv)):
            continue
        checked += 1
        if checked > 4000:
            break
        try:
            win = kmem.read_mem(nxt, 4096)   # bounded to avoid over-reading neighbours
        except gdb.error:
            continue
        # the struct must hold a base that is actually mapped in the module region,
        # else this is some other .data list that merely contains module-area pointers
        if not any(in_r(p) for p in _mod_ptrs(win, ps)):
            continue
        head_addr = image_start + off
        nn = int.from_bytes(win[0:ps], "little")  # first module's list node (or head, if 1 module)
        # Pick the inline-name offset; confirm with a second module when the list
        # has more than one (a single-module ring points straight back to the head).
        dn_pick = None
        for dn in range(ps, 200):
            if not _name_in(win, dn):
                continue
            if nn == head_addr:
                dn_pick = dn
                break
            try:
                if _name_in(kmem.read_mem(nn, dn + 56), dn):
                    dn_pick = dn
                    break
            except gdb.error:
                pass
            if dn_pick is None:
                dn_pick = dn  # fallback if no second module confirms
        if dn_pick is None:
            continue
        # Verify the ring closes back to the head (guards against false matches).
        node, ok, steps = nn, (nn == head_addr), 0
        while not ok and kmem.is_kheap(node) and steps < 8192:
            node = kmem.rd_ptr_safe(node)
            steps += 1
            if node == head_addr:
                ok = True
        if ok:
            head, name_delta = head_addr, dn_pick
            break
    if head is None:
        return []

    mods = []
    seen = set()
    node = kmem.rd_ptr_safe(head)
    while node and node != head and node not in seen and len(seen) < 4096:
        seen.add(node)
        try:
            win = kmem.read_mem(node, 4096)
        except gdb.error:
            break
        name = _name_in(win, name_delta)
        if name:
            for b in set(_mod_ptrs(win, ps)):
                if in_r(b):                 # keep only bases that are actually mapped
                    mods.append((b, name))
        node = kmem.rd_ptr_safe(node)
    mods.sort()
    return mods


# ---- Paging-mode detection (4-level vs 5-level / LA57) --------------------

def _read_creg(name):
    try:
        return int(gdb.parse_and_eval("$" + name)) & 0xFFFFFFFFFFFFFFFF
    except gdb.error:
        return None


def _detect_la57():
    """True/False when CR4.LA57 (5-level paging) can be read, else None.

    Prefers CR4 as a gdb convenience variable; falls back to parsing the QEMU
    monitor register dump when gdb doesn't expose the register that way.
    """
    cr4 = _read_creg("cr4")
    if cr4 is not None:
        return bool((cr4 >> 12) & 1)          # CR4.LA57 = bit 12
    try:
        out = gdb.execute("monitor info registers", from_tty=False, to_string=True) or ""
    except gdb.error:
        out = ""
    m = re.search(r"CR4\s*=?\s*([0-9a-fA-F]+)", out)
    if m:
        return bool((int(m.group(1), 16) >> 12) & 1)
    return None


def _has_kernel_image(items):
    """A live kernel always maps its text at 0xffffffff8……; use that as a cheap
    check that the walk used the right paging depth (a wrong depth produces no
    recognisable kernel-text mapping)."""
    return any(it["region"] == "kernel image" for it in items)


def _sample_bases(table_phys, level, va_prefix, shifts, bits, out, limit):
    """Collect up to `limit` (va - phys) values from leaves under a subtree."""
    if len(out) >= limit:
        return
    vals = _read_phys_monitor(table_phys, 512)   # base not yet known: use monitor
    shift = shifts[level]
    for i, e in enumerate(vals):
        if len(out) >= limit:
            return
        if not (e & 1):
            continue
        va = va_prefix | (i << shift)
        is_leaf = level == len(shifts) - 1 or (shift in (21, 30) and (e >> 7) & 1)
        if is_leaf:
            out.append(_canon(va, bits) - (e & _FRAME[shift]))
        else:
            _sample_bases(e & _PHYS, level + 1, va, shifts, bits, out, limit)


def _find_page_offset_base(root_phys, levels):
    """Locate the kernel direct-map base (page_offset_base) with no symbols.

    The direct map is the one top-level subtree that linearly maps physical RAM:
    every leaf satisfies va - phys == const. We sample a few leaves per candidate
    subtree (over `monitor xp`; a handful of reads) and accept the base when it is
    constant, 1 GiB-aligned (the randomisation granularity) and inside the
    direct-map window — which survives KASLR of the base. Returns the base or None;
    None just means the walk keeps using `monitor xp` (correct, only slower).
    """
    shifts = _level_shifts(levels)
    bits = _va_bits(levels)
    lay = _LAYOUT[5 if levels >= 5 else 4]
    top = _read_phys_monitor(root_phys, 512)
    for i, e in enumerate(top):
        if not (e & 1) or ((e >> 7) & 1):        # present inner node only
            continue
        va_prefix = i << shifts[0]
        if not (lay["direct_map"] <= _canon(va_prefix, bits) < lay["vmalloc"]):
            continue
        out = []
        _sample_bases(e & _PHYS, 1, va_prefix, shifts, bits, out, 8)
        if len(out) >= 2 and len(set(out)) == 1:
            base = out[0]
            if base % (1 << 30) == 0 and lay["direct_map"] <= base < lay["vmalloc"]:
                return base
    return None


def _walk_autodetect(cr3):
    """Walk the page tables, auto-selecting 4- vs 5-level paging.

    When CR4.LA57 is readable it is authoritative — we walk exactly once at that
    depth (a second full walk over millions of direct-map PTEs would be far too
    slow). Only when CR4 can't be read do we probe: try 4-level, and fall back to
    5-level if the walk recovers no kernel text. Returns (levels, items, hint).
    """
    global _POB
    la57 = _detect_la57()
    if la57 is not None:
        levels = 5 if la57 else 4
        _POB = _find_page_offset_base(cr3 & _PHYS, levels)  # enable fast reads
        return levels, _walk(cr3, levels), la57
    # CR4 unreadable: probe depth by whether the walk recovers the kernel image.
    results = {}
    for levels in (4, 5):
        _POB = _find_page_offset_base(cr3 & _PHYS, levels)
        results[levels] = _walk(cr3, levels)
        if _has_kernel_image(results[levels]):
            return levels, results[levels], None
    return 4, results[4], None


def _kvmmap_sync(server, args=None):
    try:
        cr3 = int(gdb.parse_and_eval("$cr3")) & 0xFFFFFFFFFFFFFFFF
    except gdb.error as exc:
        server.state.set({"ranges": [], "error": "cannot read $cr3: %s" % exc})
        print("[kvmmap] cannot read $cr3 — attach to a live x86-64 target: %s" % exc)
        return
    kmem.reset_paging_cache()   # re-probe paging mode for shared is_kheap() tests
    levels, items, la57 = _walk_autodetect(cr3)
    paging = "%d-level%s" % (levels, " (LA57)" if levels >= 5 else "")
    if not items:
        server._kvmmap_items = []
        server.state.set({"count": 0, "cr3": "0x%x" % cr3, "paging": paging,
                          "error": "no mappings read — is this a QEMU target "
                                   "(page tables are read over `monitor xp`)?"})
        print("[kvmmap] no mappings — need a QEMU target with a monitor")
        return

    # Best-effort: label modules-region rows with their owning module name.
    global _MODS_CACHE
    modnote = ""
    if any(it["region"] == "modules" for it in items):
        if _MODS_CACHE is None:
            mod_ranges = [(int(it["va"], 16), int(it["va_end"], 16))
                          for it in items if it["region"] == "modules"]
            _MODS_CACHE = _discover_modules(mod_ranges)
        mods = _MODS_CACHE
        if mods:
            import bisect
            bases = [m[0] for m in mods]
            for it in items:
                if it["region"] == "modules":
                    i = bisect.bisect_right(bases, int(it["va"], 16)) - 1
                    it["module"] = mods[i][1] if i >= 0 else ""
            from collections import defaultdict
            byname = defaultdict(list)
            for b, n in mods:
                byname[n].append(b)
            print("[kvmmap] resolved %d base(s) across %d module name(s):"
                  % (len(mods), len(byname)))
            for n in list(byname)[:30]:
                print("[kvmmap]   %s: %s" % (n, ", ".join("0x%x" % b for b in sorted(byname[n]))))
        else:
            modnote = ("module names unavailable — could not scan the `modules` "
                       "list (need kernel context: kernel VAs aren't readable from "
                       "userspace under KPTI; be stopped in the kernel)")
            print("[kvmmap] %s" % modnote)

    # Keep the (already run-length-collapsed) list on the server; the 1s poll only
    # carries a small summary and the page fetches the list once per sync.
    server._kvmmap_items = items
    state = {"count": len(items), "cr3": "0x%x" % cr3, "paging": paging}
    reads = "direct map" if _POB is not None else "monitor xp"
    state["reads"] = reads
    if _POB is not None:
        state["pob"] = "0x%x" % _POB
    if la57 is None:
        state["pagingnote"] = ("paging depth auto-detected (CR4 unreadable); "
                               "confirmed by the kernel-text mapping")
    if modnote:
        state["modnote"] = modnote
    server.state.set(state)
    pob = (" via direct map @ 0x%x" % _POB) if _POB is not None else " via monitor xp"
    print("[kvmmap] synced %d entries from CR3=0x%x (%s paging, read%s)"
          % (len(items), cr3, paging, pob))


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
