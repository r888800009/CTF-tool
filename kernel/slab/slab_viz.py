"""Linux SLUB slab-cache visualizer (GDB plugin).

Source this in gdb while debugging a Linux kernel that has debug info (a vmlinux
built with DWARF) through a QEMU gdb stub. It walks the kernel's `slab_caches`
list and shows every `kmem_cache` — object/slab sizes, objects per slab, and
per-node slab/object counts — as a sortable table in the browser, like a richer
`/proc/slabinfo`.

    (gdb) source kernel/slab/slab_viz.py
    (gdb) slabviz sync      # walk slab_caches now and push the table

Targets the SLUB allocator (the kernel default). Every field is read defensively
so a differing kernel version degrades to showing what it can. Shared server /
command / reload machinery lives in kernel/regviz_common.py.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import importlib  # noqa: E402
import regviz_common  # noqa: E402

importlib.reload(regviz_common)  # pick up edits to the shared module on re-source

import gdb  # noqa: E402  (provided by the gdb Python runtime)


def _ptr_size():
    try:
        return int(gdb.parse_and_eval("sizeof(void *)"))
    except Exception:  # noqa: BLE001
        return 8


def _read_mem(addr, n):
    """Raw memory read → bytes (works from the symbol addresses alone)."""
    return bytes(gdb.selected_inferior().read_memory(addr, n))


def _sym_addr(name):
    """Address of a symbol via any means gdb offers — debug info, the ELF minimal
    symbol table (no DWARF needed), or a global symbol — or None if unknown."""
    try:
        return int(gdb.parse_and_eval("&" + name))
    except gdb.error:
        pass
    try:
        ms = gdb.lookup_minimal_symbol(name)
        if ms is not None:
            fn = getattr(ms, "value_address", None)
            if fn:
                a = int(fn())
                if a:
                    return a
            a = int(ms.value().address)  # older gdb
            if a:
                return a
    except Exception:  # noqa: BLE001
        pass
    try:
        sym = gdb.lookup_global_symbol(name)
        if sym is not None:
            a = int(sym.value().address)
            if a:
                return a
    except Exception:  # noqa: BLE001
        pass
    return None


def _rd_uint(addr, n):
    return int.from_bytes(_read_mem(addr, n), "little")


def _rd_ptr(addr):
    return _rd_uint(addr, _ptr_size())


def _field_off(t, name):
    """Byte offset of a named field in a struct type, or None."""
    try:
        for f in t.fields():
            if f.name == name and getattr(f, "bitpos", None) is not None:
                return f.bitpos // 8
    except Exception:  # noqa: BLE001
        pass
    return None


def _field_int(val, *names):
    """First readable integer field among `names`, else None."""
    for n in names:
        try:
            return int(val[n])
        except Exception:  # noqa: BLE001
            continue
    return None


def _atomic(node, name):
    """Read an atomic_long_t/atomic_t field (its `.counter`), else None."""
    try:
        return int(node[name]["counter"])
    except Exception:  # noqa: BLE001
        try:
            return int(node[name])
        except Exception:  # noqa: BLE001
            return None


def _summarize(cache):
    """One row of the slab table from a `struct kmem_cache` gdb.Value."""
    d = {}
    try:
        d["name"] = cache["name"].string()
    except Exception:  # noqa: BLE001
        d["name"] = "?"
    d["object_size"] = _field_int(cache, "object_size", "objsize")
    d["size"] = _field_int(cache, "size")
    d["offset"] = _field_int(cache, "offset")
    flags = _field_int(cache, "flags")
    d["flags"] = None if flags is None else "0x%x" % (flags & 0xFFFFFFFF)

    # oo packs (order << 16) | objects-per-slab.
    try:
        x = int(cache["oo"]["x"])
        d["order"] = x >> 16
        d["objs_per_slab"] = x & 0xFFFF
    except Exception:  # noqa: BLE001
        d["order"] = None
        d["objs_per_slab"] = None

    # Per-NUMA-node counts, summed across nodes.
    nr_slabs = total_objects = nr_partial = 0
    have = False
    try:
        nnodes = int(gdb.parse_and_eval("nr_node_ids"))
    except Exception:  # noqa: BLE001
        nnodes = 1
    try:
        node_arr = cache["node"]
        for n in range(max(1, nnodes)):
            ptr = node_arr[n]
            if int(ptr) == 0:
                continue
            nd = ptr.dereference()
            have = True
            v = _atomic(nd, "nr_slabs")
            if v is not None:
                nr_slabs += v
            v = _atomic(nd, "total_objects")
            if v is not None:
                total_objects += v
            try:
                nr_partial += int(nd["nr_partial"])
            except Exception:  # noqa: BLE001
                pass
    except Exception:  # noqa: BLE001
        pass
    d["nr_slabs"] = nr_slabs if have else None
    d["total_objects"] = total_objects if have else None
    d["nr_partial"] = nr_partial if have else None

    try:
        d["addr"] = "0x%x" % int(cache.address)
    except Exception:  # noqa: BLE001
        d["addr"] = None
    return d


def _kmem_cache_type():
    """Resolve the complete `struct kmem_cache` type.

    `gdb.lookup_type("struct kmem_cache")` can fail ("No struct type named
    kmem_cache") or return an opaque forward declaration on some vmlinux builds,
    so fall back to deriving the type from a global that is declared as
    `struct kmem_cache *` (both SLAB and SLUB define these in mm/slab_common.c).
    """
    try:
        t = gdb.lookup_type("struct kmem_cache")
        t.fields()  # raises TypeError if this is only a forward declaration
        return t
    except (gdb.error, TypeError, RuntimeError):
        pass
    # Derive the complete type from any expression known to be a struct kmem_cache
    # (a pointer global, its dereference, or a kmalloc_caches slot).
    for expr in ("kmem_cache", "kmem_cache_node", "*kmem_cache",
                 "kmalloc_caches[0]", "kmalloc_caches[0][0]"):
        try:
            t = gdb.parse_and_eval(expr).type.strip_typedefs()
            while t.code in (gdb.TYPE_CODE_PTR, gdb.TYPE_CODE_ARRAY):
                t = t.target().strip_typedefs()
            t.fields()  # ensure it is a complete struct
            return t
        except (gdb.error, TypeError, RuntimeError):
            continue
    raise gdb.error(
        "could not resolve 'struct kmem_cache' — load a vmlinux with full debug "
        "info (DWARF) for the running kernel")


_SCAN_MAXOFF = 4096      # bytes of a kmem_cache to scan for a field
_BRUTE_LIST_MAX = 768    # list-offset search bound when there is no anchor
_BRUTE_NAME_MAX = 768    # name-offset search bound in the joint brute force


def _rd_ptr_safe(addr):
    try:
        return _rd_ptr(addr)
    except gdb.error:
        return 0


def _read_cstr(addr, maxlen=48):
    if not addr:
        return None
    try:
        raw = _read_mem(addr, maxlen)
    except gdb.error:
        return None
    z = raw.find(b"\x00")
    if z >= 0:
        raw = raw[:z]
    try:
        return raw.decode("ascii")
    except Exception:  # noqa: BLE001
        return None


def _looks_like_name(s):
    if not s or not (1 <= len(s) <= 40):
        return False
    return all(c.isalnum() or c in "-_.: /" for c in s) and any(c.isalnum() for c in s)


def _enumerate_nodes(head):
    """Ring of list_head node addresses reachable from `head`, via raw memory."""
    nodes, seen = [], set()
    node = _rd_ptr_safe(head)
    while node and node != head and node not in seen and len(nodes) < 1000000:
        seen.add(node)
        nodes.append(node)
        node = _rd_ptr_safe(node)
    return nodes


def _anchor_base():
    """A known kmem_cache instance address from a symbol (needs no type info)."""
    for sym in ("kmem_cache", "kmem_cache_node"):
        addr = _sym_addr(sym)
        if addr is None:
            continue
        try:
            inst = _rd_ptr(addr)
        except gdb.error:
            continue
        if inst:
            return inst
    return None


def _name_off_for(bases, ptr, maxoff=_SCAN_MAXOFF, sample_n=16):
    """Smallest field offset whose pointer yields a plausible name for most of
    the sampled caches — i.e. the `name` char* member, found by scanning."""
    sample = bases[:sample_n]
    if not sample:
        return None
    need = max(3, int(0.8 * len(sample)))
    for o in range(0, maxoff, ptr):
        good = sum(1 for b in sample if _looks_like_name(_read_cstr(_rd_ptr_safe(b + o))))
        if good >= need:
            return o
    return None


def _decode_scan(nodes, list_off, name_off):
    """Build cache rows (name + address) from ring nodes and discovered offsets."""
    caches = []
    for n in nodes:
        base = n - list_off
        caches.append({
            "name": _read_cstr(_rd_ptr_safe(base + name_off)),
            "addr": "0x%x" % base,
            "object_size": None, "size": None, "offset": None,
            "objs_per_slab": None, "order": None,
            "nr_slabs": None, "total_objects": None, "nr_partial": None, "flags": None,
        })
    caches.sort(key=lambda c: (c.get("name") or "").lower())
    return caches


def _scan_caches(nodes):
    """Discover the layout when the ring head is known: list-offset from the
    `kmem_cache` anchor or a bounded brute force, name-offset from the printable-
    name heuristic."""
    ptr = _ptr_size()
    nodeset = set(nodes)
    list_off = None
    anchor = _anchor_base()
    if anchor is not None:
        for o in range(0, _SCAN_MAXOFF, 8):
            if (anchor + o) in nodeset:
                list_off = o
                break
    name_off = None
    if list_off is not None:
        name_off = _name_off_for([n - list_off for n in nodes], ptr)
    if list_off is None or name_off is None:
        for lo in range(0, _BRUTE_LIST_MAX, 8):
            no = _name_off_for([n - lo for n in nodes], ptr, maxoff=_BRUTE_NAME_MAX, sample_n=8)
            if no is not None:
                list_off, name_off = lo, no
                break
    if list_off is None or name_off is None:
        raise gdb.error("memory scan could not locate the kmem_cache layout")
    return _decode_scan(nodes, list_off, name_off), {
        "mode": "scan", "list_off": list_off, "name_off": name_off}


# ---- Fully automatic discovery: no symbols, no guest cooperation ----------
_AUTO_RANGE = 96 * 1024 * 1024    # kernel-image bytes to scan from the text anchor
_AUTO_CHUNK = 1 * 1024 * 1024
_AUTO_CACHE = None                # remembered {anchor_base, list_off, name_off}


def _is_ktext(v):
    return 0xFFFFFFFF80000000 <= v <= 0xFFFFFFFFFFFFFFFF


def _is_kheap(v):
    # kernel direct map / vmalloc: canonical high half, below the text window
    return (v >> 48) == 0xFFFF and 0xFFFF800000000000 <= v < 0xFFFFFFFF80000000


def _text_anchor():
    """A kernel .text address to anchor the image scan: $pc if it is in the
    kernel, else the first kernel-text value found on the stack."""
    try:
        pc = int(gdb.parse_and_eval("$pc"))
        if _is_ktext(pc):
            return pc
    except gdb.error:
        pass
    try:
        sp = int(gdb.parse_and_eval("$sp"))
        blob = _read_mem(sp, 64 * 1024)
    except gdb.error:
        return None
    ps = _ptr_size()
    for i in range(0, len(blob) - ps, ps):
        v = int.from_bytes(blob[i:i + ps], "little")
        if _is_ktext(v):
            return v
    return None


def _read_image(start, rng, chunk=_AUTO_CHUNK):
    """Read up to `rng` bytes from `start`, stopping at the first unmapped gap."""
    buf = bytearray()
    off = 0
    while off < rng:
        n = min(chunk, rng - off)
        try:
            buf += _read_mem(start + off, n)
        except gdb.error:
            break
        off += n
    return bytes(buf)


def _auto_discover():
    """Locate the kmem_cache ring purely from memory, with no symbols.

    Anchor on a kernel .text address, read the kernel image, find the
    "kmem_cache" name string in rodata, then a .data pointer to a heap instance
    whose name field points at that string (giving the name offset), and finally
    the list offset from that instance's ring links. Returns
    ``{anchor_base, list_off, name_off}`` or None.
    """
    anchor = _text_anchor()
    if anchor is None:
        return None
    ps = _ptr_size()
    image_start = anchor & ~0x1FFFFF
    buf = _read_image(image_start, _AUTO_RANGE)
    if not buf:
        return None

    needle = b"kmem_cache\x00"
    s_positions = []
    i = buf.find(needle)
    while i != -1 and len(s_positions) < 64:
        s_positions.append(i)
        i = buf.find(needle, i + 1)
    if not s_positions:
        return None
    s_addrs = set(image_start + p for p in s_positions)
    data_from = max(s_positions) & ~(ps - 1)  # globals live after the rodata strings

    inst = None
    name_off = None
    for pos in range(data_from, len(buf) - ps, ps):
        v = int.from_bytes(buf[pos:pos + ps], "little")
        if not _is_kheap(v):
            continue
        try:
            win = _read_mem(v, 256)
        except gdb.error:
            continue
        for o in range(0, len(win) - ps, ps):
            if int.from_bytes(win[o:o + ps], "little") in s_addrs:
                inst, name_off = v, o
                break
        if inst is not None:
            break
    if inst is None:
        return None

    for o in range(0, _SCAN_MAXOFF, 8):
        node = _rd_ptr_safe(inst + o)
        if not _is_kheap(node):
            continue
        if _looks_like_name(_read_cstr(_rd_ptr_safe((node - o) + name_off))):
            return {"anchor_base": inst, "list_off": o, "name_off": name_off}
    return None


def _enumerate_ring(start_node):
    """All list_head nodes on the ring that `start_node` belongs to."""
    nodes, seen = [start_node], {start_node}
    node = _rd_ptr_safe(start_node)
    while node and node != start_node and node not in seen and len(nodes) < 1000000:
        seen.add(node)
        nodes.append(node)
        node = _rd_ptr_safe(node)
    return nodes


def _walk_caches(head_hint=None):
    """Every kmem_cache, traversed directly through memory. Returns (caches, meta).

    - head_hint given → walk from that slab_caches address (pure memory);
    - else if a kernel symbol resolves → walk from it;
    - else discover the ring fully automatically by scanning memory, with no
      symbols and no guest cooperation (:func:`_auto_discover`).
    Fields are decoded from DWARF when the struct type is available, otherwise
    only name and address are recovered by scanning.
    """
    head = head_hint
    if head is None:
        for hsym in ("slab_caches", "cache_chain"):
            head = _sym_addr(hsym)
            if head is not None:
                break

    if head is not None:
        nodes = _enumerate_nodes(head)
        try:
            kc = _kmem_cache_type()
        except gdb.error:
            kc = None
        if kc is not None:
            list_off = _field_off(kc, "list")
            if list_off is not None:
                kcp = kc.pointer()
                caches = [_summarize(gdb.Value(n - list_off).cast(kcp).dereference())
                          for n in nodes]
                caches.sort(key=lambda c: (c.get("name") or "").lower())
                return caches, {"mode": "debuginfo"}
        return _scan_caches(nodes)

    # No symbol and no hint: fully automatic memory discovery (cached).
    global _AUTO_CACHE
    disc = _AUTO_CACHE
    if disc is not None:
        nm = _read_cstr(_rd_ptr_safe(disc["anchor_base"] + disc["name_off"]))
        if not _looks_like_name(nm):
            disc = None
    if disc is None:
        disc = _auto_discover()
        _AUTO_CACHE = disc
    if disc is None:
        raise gdb.error(
            "no kernel symbols, and automatic memory discovery failed. Pass the "
            "slab_caches address if you have it (`slabviz sync 0x<addr>`). Auto "
            "discovery needs to be stopped in the kernel (a kernel $pc, or a kernel "
            "return address on the stack) on an x86-64 SLUB target.")
    nodes = _enumerate_ring(disc["anchor_base"] + disc["list_off"])
    return _decode_scan(nodes, disc["list_off"], disc["name_off"]), {
        "mode": "scan-auto", "list_off": disc["list_off"],
        "name_off": disc["name_off"], "anchor": "0x%x" % disc["anchor_base"]}


def _slab_sync(server, args=None):
    # `slabviz sync 0x<addr>` sets the slab_caches head directly (pure memory
    # mode, no symbols needed); the hint persists for later plain syncs.
    for tok in (args or []):
        try:
            server._slab_head = int(tok, 0)
            print("[slabviz] using slab_caches head at 0x%x (memory mode)" % server._slab_head)
        except ValueError:
            print("[slabviz] ignoring invalid address '%s'" % tok)
    head_hint = getattr(server, "_slab_head", None)
    try:
        caches, meta = _walk_caches(head_hint)
    except gdb.error as exc:
        server.state.set({"caches": [], "meta": {}, "error": str(exc)})
        print("[slabviz] could not read slab caches: %s" % exc)
        print("[slabviz] need a Linux kernel target with the 'slab_caches' symbol (SLUB)")
        return
    except Exception as exc:  # noqa: BLE001
        server.state.set({"caches": [], "meta": {}, "error": "%s: %s" % (type(exc).__name__, exc)})
        print("[slabviz] error while walking slab_caches: %s" % exc)
        return
    server.state.set({"caches": caches, "meta": meta})
    if meta.get("mode", "").startswith("scan"):
        how = "auto memory scan" if meta["mode"] == "scan-auto" else "memory scan"
        print("[slabviz] synced %d slab caches via %s "
              "(list_off=%#x, name_off=%#x; names only, no debug info)"
              % (len(caches), how, meta["list_off"], meta["name_off"]))
    else:
        print("[slabviz] synced %d slab caches (from debug info)" % len(caches))


regviz_common.install_app(
    prefix="slabviz",
    default_port=8774,
    label="slab",
    html_path=Path(__file__).resolve().parent / "slab_viz.html",
    sync_fn=_slab_sync,
    sync_hint="the slab caches",
)
