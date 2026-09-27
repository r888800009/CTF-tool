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
    for expr in ("kmem_cache", "kmem_cache_node"):
        try:
            t = gdb.parse_and_eval(expr).type.strip_typedefs()
            if t.code == gdb.TYPE_CODE_PTR:
                tt = t.target().strip_typedefs()
                tt.fields()  # ensure it is a complete struct
                return tt
        except (gdb.error, TypeError, RuntimeError):
            continue
    raise gdb.error(
        "could not resolve 'struct kmem_cache' — load a vmlinux with full debug "
        "info (DWARF) for the running kernel")


def _walk_caches():
    """Every kmem_cache reachable from the global `slab_caches` list."""
    kc = _kmem_cache_type()
    kcp = kc.pointer()
    off = None
    for f in kc.fields():
        if f.name == "list":
            off = f.bitpos // 8
            break
    if off is None:
        raise gdb.error("struct kmem_cache has no 'list' member (unexpected layout)")

    head_addr = int(gdb.parse_and_eval("&slab_caches"))
    node = int(gdb.parse_and_eval("slab_caches")["next"])
    caches = []
    guard = 0
    while node != head_addr and guard < 100000:
        guard += 1
        cache = gdb.Value(node - off).cast(kcp).dereference()
        caches.append(_summarize(cache))
        node = int(cache["list"]["next"])
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
