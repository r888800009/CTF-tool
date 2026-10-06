"""Shared pure-memory helpers for the kernel viewers.

These read guest memory and locate things from the gdb side alone — a kernel
`.text` anchor from the CPU state, a kernel-image scan, symbol lookup, C-string
reads and address-region tests — so viewers work with no vmlinux/DWARF where
possible. Both the slab viewer and the task_struct viewer build on this.
"""

import gdb  # provided by the gdb Python runtime


def ptr_size():
    try:
        return int(gdb.parse_and_eval("sizeof(void *)"))
    except Exception:  # noqa: BLE001
        return 8


def read_mem(addr, n):
    """Raw memory read → bytes."""
    return bytes(gdb.selected_inferior().read_memory(addr, n))


def rd_uint(addr, n):
    return int.from_bytes(read_mem(addr, n), "little")


def rd_ptr(addr):
    return rd_uint(addr, ptr_size())


def rd_ptr_safe(addr):
    try:
        return rd_ptr(addr)
    except gdb.error:
        return 0


def read_cstr(addr, maxlen=48):
    if not addr:
        return None
    try:
        raw = read_mem(addr, maxlen)
    except gdb.error:
        return None
    z = raw.find(b"\x00")
    if z >= 0:
        raw = raw[:z]
    try:
        return raw.decode("ascii")
    except Exception:  # noqa: BLE001
        return None


def looks_like_name(s):
    if not s or not (1 <= len(s) <= 40):
        return False
    return all(c.isalnum() or c in "-_.: /" for c in s) and any(c.isalnum() for c in s)


_LA57 = None   # cached paging mode for this session (None = not yet probed)


def la57():
    """True if the CPU runs 5-level paging (CR4.LA57), else False.

    Auto-detected from CR4 (bit 12) and cached — the kernel-half base moves from
    0xffff800000000000 (4-level) down to 0xff00000000000000 (5-level), so the
    region tests below must follow it. Cached because they run in tight scan
    loops; re-sourcing a viewer reloads this module and clears the cache. When
    CR4 can't be read we assume 4-level (the common case)."""
    global _LA57
    if _LA57 is None:
        try:
            cr4 = int(gdb.parse_and_eval("$cr4")) & 0xFFFFFFFFFFFFFFFF
            _LA57 = bool((cr4 >> 12) & 1)      # cache only a successful read
        except gdb.error:
            return False                       # no target yet — retry next call
    return _LA57


def reset_paging_cache():
    """Forget the cached paging mode (call after switching targets)."""
    global _LA57
    _LA57 = None


def _kern_half_base():
    """Lowest canonical kernel-half VA for the active paging mode."""
    return 0xFF00000000000000 if la57() else 0xFFFF800000000000


def user_top():
    """Exclusive upper bound of the canonical user half for the active paging
    mode: 47-bit (4-level) or 57-bit (5-level / LA57)."""
    return 0x0100000000000000 if la57() else 0x0000800000000000


def is_ktext(v):
    return 0xFFFFFFFF80000000 <= v <= 0xFFFFFFFFFFFFFFFF


def is_kheap(v):
    # kernel direct map / vmalloc / vmemmap: canonical high half, below the text
    # window. The lower bound tracks the paging mode (4- vs 5-level).
    return _kern_half_base() <= v < 0xFFFFFFFF80000000


def sym_addr(name):
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


def text_anchor():
    """A kernel .text address to anchor an image scan: $pc if it is in the
    kernel, else the first kernel-text value found on the stack."""
    try:
        pc = int(gdb.parse_and_eval("$pc"))
        if is_ktext(pc):
            return pc
    except gdb.error:
        pass
    try:
        sp = int(gdb.parse_and_eval("$sp"))
        blob = read_mem(sp, 64 * 1024)
    except gdb.error:
        return None
    ps = ptr_size()
    for i in range(0, len(blob) - ps, ps):
        v = int.from_bytes(blob[i:i + ps], "little")
        if is_ktext(v):
            return v
    return None


def read_image(start, rng, chunk=1024 * 1024):
    """Read up to `rng` bytes from `start`, stopping at the first unmapped gap."""
    buf = bytearray()
    off = 0
    while off < rng:
        n = min(chunk, rng - off)
        try:
            buf += read_mem(start + off, n)
        except gdb.error:
            break
        off += n
    return bytes(buf)
