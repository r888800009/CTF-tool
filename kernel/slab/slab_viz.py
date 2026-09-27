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


def _walk_caches():
    """Every kmem_cache reachable from the global `slab_caches` list.

    Traversal is done purely through memory: only the address of the
    `slab_caches` symbol is needed, and the list ring is followed by reading each
    `list_head.next` pointer (at offset 0) directly, so it does not depend on the
    `struct kmem_cache` / `struct list_head` types being resolvable by name. The
    container type is still needed to *decode* each cache's fields.
    """
    try:
        head = int(gdb.parse_and_eval("&slab_caches"))
    except gdb.error:
        raise gdb.error("symbol 'slab_caches' not found — load the kernel symbols")

    # Follow the ring by reading raw `next` pointers from memory.
    nodes = []
    seen = set()
    node = _rd_ptr(head)
    while node and node != head and node not in seen and len(nodes) < 1000000:
        seen.add(node)
        nodes.append(node)
        node = _rd_ptr(node)

    kc = _kmem_cache_type()
    kcp = kc.pointer()
    list_off = _field_off(kc, "list")
    if list_off is None:
        raise gdb.error("struct kmem_cache has no 'list' member (unexpected layout)")

    caches = []
    for n in nodes:
        cache = gdb.Value(n - list_off).cast(kcp).dereference()
        caches.append(_summarize(cache))
    caches.sort(key=lambda c: (c.get("name") or "").lower())
    return caches


def _slab_sync(server):
    try:
        caches = _walk_caches()
    except gdb.error as exc:
        server.state.set({"caches": [], "error": str(exc)})
        print("[slabviz] could not read slab_caches: %s" % exc)
        print("[slabviz] need a Linux kernel target with debug info (vmlinux) using SLUB")
        return
    except Exception as exc:  # noqa: BLE001
        server.state.set({"caches": [], "error": "%s: %s" % (type(exc).__name__, exc)})
        print("[slabviz] error while walking slab_caches: %s" % exc)
        return
    server.state.set({"caches": caches})
    print("[slabviz] synced %d slab caches" % len(caches))


regviz_common.install_app(
    prefix="slabviz",
    default_port=8774,
    label="slab",
    html_path=Path(__file__).resolve().parent / "slab_viz.html",
    sync_fn=_slab_sync,
    sync_hint="the slab caches",
)
