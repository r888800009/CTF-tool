"""Linux task_struct (process) viewer — a GDB plugin.

Scans the kernel's process list out of memory and shows every task's PID and
comm (name) in the browser, like `ps` — purely from the gdb side, no symbols or
guest cooperation needed:

  * anchor on a kernel .text address ($pc, or a kernel return address on the
    stack) and read the kernel image;
  * find init_task's `comm` string ("swapper/0") in the image — init_task is a
    static struct in .data — which locates init_task;
  * find its `tasks` list_head next to it (a pair of kernel-heap pointers whose
    comm-relative offset yields a printable name for the next task);
  * walk the `tasks` ring, reading each task's comm at the same offset, and
    discover the `pid` field offset heuristically (pid == tgid, a small varied
    positive int for the group leaders on this list).

    (gdb) source kernel/task/task_viz.py
    (gdb) taskviz sync

Targets x86-64. Shared server lives in kernel/regviz_common.py; shared memory
helpers in kernel/kmem.py.
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

_IMG_RANGE = 96 * 1024 * 1024
_CACHE = None  # {tasks_head, comm_delta, mm_delta, kver}

# The maple tree (VMA container since Linux 6.1) tags internal-node pointers: the
# low byte holds (node_type << 3) | 2 and the node itself is 256-byte aligned, so
# an enode is recovered with & ~0xff. Ordinary object pointers are only 8-aligned.
_MAPLE_MIN = (6, 1)
_MAPLE_TYPE = {0: "dense", 1: "leaf_64", 2: "range_64", 3: "arange_64"}
# (slot-array offset, slot count) per maple node type on 64-bit. A node is 256
# bytes: parent@0, then pivots, then the slots. leaf_64/range_64 hold 16 slots at
# offset 128 (15 pivots @8..127); arange_64 holds 10 slots at 80 (9 pivots @8..79,
# then 10 gaps); dense holds pointers from offset 0.
_MAPLE_SLOTS = {0: (0, 32), 1: (128, 16), 2: (128, 16), 3: (80, 10)}


def _child_addr(w):
    """Kernel-heap address a container word points at, or None.

    Distinguishes a maple internal-node pointer (low two bits == 0b10, whole low
    byte is the type tag → mask ~0xff) from an ordinary 8-aligned object pointer
    (a maple leaf entry, or an rb/list link → mask ~0x7). Object pointers are
    always ≥8-aligned, so (w & 3) == 2 uniquely marks a maple enode."""
    a = (w & ~0xFF) if (w & 3) == 2 else (w & ~0x7)
    return a if kmem.is_kheap(a) else None

_MM_WIN = 0x2000           # bytes each side of a tasks node to scan for `mm`
_VMA_MAX = 4096            # BFS object budget when walking an mm's VMAs
_VMA_OBJ = 256             # bytes read per candidate object during the VMA walk
_VMA_HEAD = 96             # bytes of a VMA scanned to validate/locate vm_mm
_VMA_RB_SCAN = 160         # bytes of a VMA scanned to locate the embedded vm_rb
_USER_TOP = 0x0000800000000000  # exclusive upper bound of the canonical user half

# vm_area_struct.vm_flags bits (stable) → permission string.
_VM_READ, _VM_WRITE, _VM_EXEC, _VM_SHARED = 0x1, 0x2, 0x4, 0x8


def _u32(addr):
    try:
        return kmem.rd_uint(addr, 4)
    except gdb.error:
        return None


def _discover(anchor=None):
    """Locate init_task's `tasks` list head and the comm offset by scanning.

    `anchor` is a kernel address to start the image scan from (any address in the
    kernel image/.text works — e.g. a "kernel image" row from kvmmap); when None
    it is taken from the CPU ($pc / a kernel return address on the stack)."""
    ps = kmem.ptr_size()
    if anchor is None:
        anchor = kmem.text_anchor()
    if anchor is None:
        return None
    image_start = anchor & ~0x1FFFFF
    buf = kmem.read_image(image_start, _IMG_RANGE)
    if not buf:
        return None

    pos = -1
    for needle in (b"swapper/0\x00", b"swapper\x00"):
        pos = buf.find(needle)
        if pos != -1:
            break
    if pos < 0:
        return None
    comm_addr = image_start + pos

    # Look near the comm string for init_task.tasks: two adjacent kernel-heap
    # pointers whose (comm - tasks) offset gives a printable comm at the next
    # task, and whose ring returns to this head.
    win = 8192
    lo = max(0, comm_addr - win - image_start) & ~(ps - 1)
    hi = min(len(buf) - 2 * ps, comm_addr + win - image_start)
    for off in range(lo, hi, ps):
        nxt = int.from_bytes(buf[off:off + ps], "little")
        prv = int.from_bytes(buf[off + ps:off + 2 * ps], "little")
        if not (kmem.is_kheap(nxt) and kmem.is_kheap(prv)):
            continue
        head = image_start + off
        delta = comm_addr - head
        if not kmem.looks_like_name(kmem.read_cstr(nxt + delta, 16)):
            continue
        # confirm the ring closes back to `head`
        node, ok = nxt, False
        for _ in range(100000):
            if node == head:
                ok = True
                break
            nn = kmem.rd_ptr_safe(node)
            if not kmem.is_kheap(nn) and nn != head:
                break
            node = nn
        if ok:
            return {"tasks_head": head, "comm_delta": delta}
    return None


def _find_pid_delta(nodes):
    """Offset (relative to a tasks node) of the `pid` field, found heuristically.

    In task_struct, `pid` and `tgid` are adjacent and equal for the thread-group
    leaders on this list; PIDs are small positive ints, unique per task. So the
    right offset is the one where most tasks read `pid == tgid` in [1, 0x400000)
    AND those values are the most *distinct* — this rejects all-zero fields and
    fields that are really (equal halves of) a pointer.
    """
    lo, hi = -2048, 2048
    wins = {}
    for node in nodes[:16]:
        try:
            wins[node] = kmem.read_mem(node + lo, hi - lo)
        except gdb.error:
            pass
    if not wins:
        return None
    n = len(wins)
    best_po, best_score = None, (0, 0)
    for po in range(lo, hi - 8, 4):
        vals = []
        for buf in wins.values():
            i = po - lo
            v = int.from_bytes(buf[i:i + 4], "little")
            v2 = int.from_bytes(buf[i + 4:i + 8], "little")
            if v == v2 and 1 <= v < 0x400000:
                vals.append(v)
        distinct = len(set(vals))
        if len(vals) >= max(3, int(0.6 * n)) and distinct >= max(3, int(0.5 * n)):
            score = (distinct, len(vals))
            if score > best_score:
                best_score, best_po = score, po
    return best_po


def _u64(buf, i):
    return int.from_bytes(buf[i:i + 8], "little")


def _vma_at(addr, mm, buf=None):
    """If `addr` is a vm_area_struct belonging to `mm`, decode it, else None.

    A VMA begins with `unsigned long vm_start, vm_end` — two ascending,
    page-aligned user addresses — and holds `struct mm_struct *vm_mm` a little
    later: offset 16 on the 6.1+ maple-tree layout, but offset 64 on older
    red-black-tree kernels (…vm_next, vm_prev, vm_rb, rb_subtree_gap come first).
    We anchor on vm_mm == mm, which is extremely specific, so we need not know the
    exact version — just scan the head for it. vm_flags (r/w/x/shared) sits two
    words past vm_mm on both layouts (vm_mm, vm_page_prot, vm_flags).
    """
    if buf is None:
        try:
            buf = kmem.read_mem(addr, _VMA_HEAD)
        except gdb.error:
            return None
    start = _u64(buf, 0)
    end = _u64(buf, 8)
    if not (0 < start < end < _USER_TOP):
        return None
    if (start | end) & 0xFFF:
        return None
    mm_off = None
    for o in range(16, min(len(buf), _VMA_HEAD) - 8, 8):
        if _u64(buf, o) == mm:
            mm_off = o
            break
    if mm_off is None:
        return None
    flags = _u64(buf, mm_off + 16) if mm_off + 24 <= len(buf) else 0
    perms = "".join(c if flags & b else "-" for c, b in
                    (("r", _VM_READ), ("w", _VM_WRITE), ("x", _VM_EXEC)))
    perms += "s" if flags & _VM_SHARED else "p"
    return {
        "addr": "0x%x" % addr,
        "start": "0x%x" % start,
        "end": "0x%x" % end,
        "size": end - start,
        "perms": perms,
        "flags": "0x%x" % (flags & 0xFFFFFFFF),
    }


def _walk_vmas(mm, budget=_VMA_MAX):
    """Every vm_area_struct of `mm`, by bounded memory BFS from the mm_struct.

    Seed from the kheap pointers in the mm_struct's head (which covers the VMA
    container — a maple tree root on 6.1+, or the mmap list on older kernels);
    then follow kheap pointers through container nodes, collecting objects that
    validate as VMAs of `mm` (:func:`_vma_at`). vm_start/vm_end being user,
    ascending and page-aligned with vm_mm == mm makes false positives vanishingly
    unlikely; a visited set and object budget bound the walk. Pivots (plain ints)
    and page-table pointers are not kheap object pointers, so they dead-end.

    Every word is resolved through :func:`_child_addr`, which strips the maple
    tree's node-type tag (masking ~0xff for tagged enodes, ~0x7 otherwise). Without
    that, a maple internal-node pointer — tagged with (type << 3) | 2 — is a
    misaligned address that reads garbage and hides every VMA."""
    if not kmem.is_kheap(mm):
        return []
    vmas, visited = {}, set()
    try:
        queue = []
        head = kmem.read_mem(mm, 512)
        for o in range(0, len(head) - 8, 8):
            p = _child_addr(_u64(head, o))
            if p is not None:
                queue.append(p)
    except gdb.error:
        return []
    steps = 0
    while queue and steps < budget:
        steps += 1
        obj = queue.pop()
        if obj in visited:
            continue
        visited.add(obj)
        try:
            buf = kmem.read_mem(obj, _VMA_OBJ)
        except gdb.error:
            continue
        v = _vma_at(obj, mm, buf[:_VMA_HEAD])
        if v is not None:
            vmas[obj] = v
        # Follow child/next pointers (maple slots/enodes, or vm_next on old kernels).
        for o in range(0, len(buf) - 8, 8):
            p = _child_addr(_u64(buf, o))
            if p is not None and p not in visited:
                queue.append(p)
    return sorted(vmas.values(), key=lambda x: int(x["start"], 16))


def _mm_delta_cheap(nodes):
    """Fast path: `mm`/`active_mm` are adjacent and, for a user process, equal and
    both point at the same kheap mm_struct (kernel threads have mm == NULL and do
    not vote). Pick the offset where most tasks show that adjacent-equal-kheap pair
    and the target actually walks out to a VMA."""
    from collections import Counter
    ps = kmem.ptr_size()
    seen = Counter()
    per_task = []
    for node in nodes[:24]:
        try:
            buf = kmem.read_mem(node - _MM_WIN, 2 * _MM_WIN)
        except gdb.error:
            continue
        offs = set()
        for o in range(0, len(buf) - 2 * ps, 8):
            a = _u64(buf, o)
            if a and a == _u64(buf, o + ps) and kmem.is_kheap(a):
                offs.add(o - _MM_WIN)
        per_task.append((node, offs))
        for o in offs:
            seen[o] += 1
    for off, _cnt in seen.most_common(24):
        ok = tested = 0
        for node, offs in per_task:
            if off not in offs:
                continue
            tested += 1
            if _walk_vmas(kmem.rd_ptr_safe(node + off), budget=400):
                ok += 1
            if tested >= 4:
                break
        if tested and ok >= max(2, tested - 1):
            return off
    return None


def _mm_delta_scan(nodes, span=0x1800, budget=64, sample=6):
    """Fallback: directly vote for the offset holding a pointer that walks out to
    VMAs, dropping the adjacent-equal assumption (which can miss, e.g. when mm and
    active_mm differ). For a few tasks, scan the window for kheap pointers whose
    target yields at least one VMA. A true mm's first VMA is a direct seed, so a
    small budget suffices and non-mm pointers are abandoned quickly.

    Both `mm` and `active_mm` (== mm on user tasks) validate; we keep the lower of
    any adjacent winning pair, i.e. `mm`, so kernel threads (mm == NULL) correctly
    show no VMAs rather than a borrowed active_mm's."""
    from collections import Counter
    votes = Counter()
    for node in nodes[:sample]:
        try:
            buf = kmem.read_mem(node - span, 2 * span)
        except gdb.error:
            continue
        for o in range(0, len(buf) - 8, 8):
            p = _child_addr(_u64(buf, o))
            if p is not None and _walk_vmas(p, budget=budget):
                votes[o - span] += 1
    if not votes:
        return None
    winners = {off for off, c in votes.items() if c >= 2}
    if not winners:
        return None
    kept = {off for off in winners if (off - 8) not in winners}  # drop active_mm
    return max(kept, key=lambda o: (votes[o], -o))


def _find_mm_delta(nodes):
    """Offset (relative to a tasks node) of the `mm` pointer. Try the fast
    adjacent-equal heuristic, then a direct validated scan as a fallback."""
    return _mm_delta_cheap(nodes) or _mm_delta_scan(nodes)


def _discover_vma_rb(bases):
    """Offset of the embedded `struct rb_node vm_rb` inside a vm_area_struct.

    Older kernels index VMAs with a red-black tree (`mm_rb`), each VMA carrying an
    rb_node {`__rb_parent_color`, `rb_right`, `rb_left`}. The right offset is the
    one where, for every VMA, the two child words are either NULL or point at
    another VMA's rb_node (child_base + off), and the parent word (low bits are the
    colour, masked off) is NULL (the root) or likewise points at a VMA's rb_node —
    with a real number of those links present (which rules out all-zero regions and
    the maple-tree layout, where there is no such node)."""
    S = set(bases)
    heads = {}
    for b in bases:
        try:
            heads[b] = kmem.read_mem(b, _VMA_RB_SCAN)
        except gdb.error:
            pass
    if len(heads) < 3:
        return None
    best_off, best_ref = None, 0
    for o in range(0, _VMA_RB_SCAN - 24, 8):
        ref, ok = 0, True
        for buf in heads.values():
            pc = _u64(buf, o) & ~3
            r = _u64(buf, o + 8)
            l = _u64(buf, o + 16)
            if not ((pc == 0 or (pc - o) in S)
                    and (r == 0 or (r - o) in S)
                    and (l == 0 or (l - o) in S)):
                ok = False
                break
            ref += (1 if pc and (pc - o) in S else 0)
            ref += (1 if r and (r - o) in S else 0)
            ref += (1 if l and (l - o) in S else 0)
        if ok and ref > best_ref:
            best_ref, best_off = ref, o
    return best_off if best_off is not None and best_ref >= len(heads) else None


def _rb_root(mm, vm_rb_off, bases):
    """The root rb_node address, from `mm_rb.rb_node` — a pointer in the mm_struct
    to some VMA's rb_node (root_base + vm_rb_off)."""
    S = set(bases)
    try:
        head = kmem.read_mem(mm, 512)
    except gdb.error:
        return None
    for o in range(0, len(head) - 8, 8):
        w = _u64(head, o)
        if w and (w - vm_rb_off) in S:
            return w
    return None


def _build_rb(rbnode, vm_rb_off, fields, depth=0, seen=None):
    """Nested {colour, VMA fields, left, right} tree from a root rb_node address."""
    if seen is None:
        seen = set()
    if not rbnode or rbnode in seen or depth > 64:
        return None
    seen.add(rbnode)
    try:
        buf = kmem.read_mem(rbnode, 24)
    except gdb.error:
        return None
    pc, right, left = _u64(buf, 0), _u64(buf, 8), _u64(buf, 16)
    f = fields.get(rbnode - vm_rb_off, {})
    return {
        "addr": "0x%x" % (rbnode - vm_rb_off),
        "color": "black" if (pc & 1) else "red",
        "start": f.get("start"), "end": f.get("end"),
        "perms": f.get("perms"), "size": f.get("size"),
        "left": _build_rb(left, vm_rb_off, fields, depth + 1, seen),
        "right": _build_rb(right, vm_rb_off, fields, depth + 1, seen),
    }


def _detect_kernel_version(anchor=None):
    """Kernel version, auto-detected from the `Linux version …` banner in the
    kernel image (always present in .rodata) — needs no symbols. Returns
    {major, minor, patch, banner} or None."""
    if anchor is None:
        anchor = kmem.text_anchor()
    if anchor is None:
        return None
    image_start = anchor & ~0x1FFFFF
    buf = kmem.read_image(image_start, _IMG_RANGE)
    if not buf:
        return None
    i = buf.find(b"Linux version ")
    if i < 0:
        return None
    line = buf[i:i + 160].split(b"\x00", 1)[0].split(b"\n", 1)[0].decode("latin1", "replace")
    m = re.match(r"Linux version (\d+)\.(\d+)\.(\d+)", line)
    if not m:
        return None
    return {"major": int(m.group(1)), "minor": int(m.group(2)),
            "patch": int(m.group(3)), "banner": line.split(" (", 1)[0]}


def _is_maple(kver):
    """True if this kernel indexes VMAs with a maple tree (Linux ≥ 6.1)."""
    return bool(kver) and (kver["major"], kver["minor"]) >= _MAPLE_MIN


def _maple_root(mm):
    """The maple tree root enode from `mm_mt.ma_root` — a tagged internal-node
    pointer ((w & 3) == 2) sitting in the mm_struct head."""
    try:
        head = kmem.read_mem(mm, 512)
    except gdb.error:
        return None
    for o in range(0, len(head) - 8, 8):
        w = _u64(head, o)
        if (w & 3) == 2 and kmem.is_kheap(w & ~0xFF):
            return w
    return None


def _maple_debug(mm):
    """Raw bytes of the mm head and the maple root node, for diagnosing an
    incomplete walk (returned only when the maple walk found suspiciously few
    VMAs). All hex so the browser can render a region-coloured hexdump."""
    d = {"mm": "0x%x" % mm}
    try:
        d["mm_head"] = kmem.read_mem(mm, 64).hex()
    except gdb.error:
        return d
    root = _maple_root(mm)
    if root is None:
        d["note"] = "no maple root ((w&3)==2 kheap word) found in mm head"
        return d
    d["ma_root"] = "0x%x" % root
    d["root_type"] = _MAPLE_TYPE.get((root >> 3) & 0xF, "?")
    node = root & ~0xFF
    d["root_node_addr"] = "0x%x" % node
    try:
        d["root_node"] = kmem.read_mem(node, 256).hex()
    except gdb.error:
        pass
    return d


def _maple_slots(node, typ):
    """Yield the non-zero slot values of a maple node, by its type's slot layout.

    A maple node is 256 bytes, 256-aligned; only the type-specific slot array holds
    child enodes / stored entries — walking exactly that (rather than the whole
    node) skips the parent pointer, pivots and gaps, so nothing is mistaken for an
    entry and, crucially, the walk follows only the tree (no budget, no wandering
    into unrelated kernel-heap objects, which was losing all but one VMA)."""
    slot_off, nslots = _MAPLE_SLOTS.get(typ, (0, 32))
    try:
        buf = kmem.read_mem(node, 256)
    except gdb.error:
        return
    for i in range(nslots):
        o = slot_off + i * 8
        if o + 8 > len(buf):
            break
        w = _u64(buf, o)
        if w:
            yield w


def _maple_collect(enode, mm, out, seen, depth=0):
    """Walk the maple tree from `enode`, filling `out` {addr: vma} with every VMA.

    Each slot is either a tagged child enode ((w & 3) == 2 → recurse) or, at a leaf,
    a clean pointer to a stored vm_area_struct (validate against `mm`)."""
    node = enode & ~0xFF
    if node in seen or depth > 32 or not kmem.is_kheap(node):
        return
    seen.add(node)
    for w in _maple_slots(node, (enode >> 3) & 0xF):
        if (w & 3) == 2 and kmem.is_kheap(w & ~0xFF):
            _maple_collect(w, mm, out, seen, depth + 1)
        else:
            a = w & ~0x7
            if kmem.is_kheap(a) and a not in out:
                v = _vma_at(a, mm)
                if v is not None:
                    out[a] = v


def _maple_vmas(mm):
    """All VMAs of `mm` via a direct maple-tree walk (Linux ≥ 6.1). Falls back to
    the generic BFS if no maple root is found in the mm head."""
    root = _maple_root(mm)
    if root is None:
        return _walk_vmas(mm)
    out = {}
    _maple_collect(root, mm, out, set())
    return sorted(out.values(), key=lambda x: int(x["start"], 16))


def _build_maple(enode, fields, depth=0, seen=None):
    """Nested maple-tree node {type, children, vmas} for drawing, walking the same
    type-specific slots as :func:`_maple_collect`. Child enodes (tagged) recurse;
    clean slot pointers that resolve to a known VMA (`fields`) are leaf entries."""
    if seen is None:
        seen = set()
    node = enode & ~0xFF
    if not kmem.is_kheap(node) or node in seen or depth > 32:
        return None
    seen.add(node)
    children, vmas = [], []
    for w in _maple_slots(node, (enode >> 3) & 0xF):
        if (w & 3) == 2 and kmem.is_kheap(w & ~0xFF):
            c = _build_maple(w, fields, depth + 1, seen)
            if c is not None:
                children.append(c)
        else:
            a = w & ~0x7
            if a in fields:
                vmas.append(fields[a])
    return {
        "addr": "0x%x" % node,
        "type": (enode >> 3) & 0xF,
        "type_name": _MAPLE_TYPE.get((enode >> 3) & 0xF, "?"),
        "vmas": vmas,
        "children": children,
    }


def _vma_tree(mm, bases, fields, kver):
    """Reconstruct the VMA container as a drawable tree, choosing by kernel version:
    a maple tree on Linux ≥ 6.1, else a red-black tree. If the version is unknown,
    try both. Returns {"kind": "maple"|"rbtree", ...} or None."""
    def maple():
        root = _maple_root(mm)
        t = _build_maple(root, fields) if root else None
        return {"kind": "maple", "root": t} if t else None

    def rbtree():
        if len(bases) < 3:
            return None
        off = _discover_vma_rb(bases)
        if off is None:
            return None
        r = _rb_root(mm, off, bases)
        if r is None:
            return None
        return {"kind": "rbtree", "vm_rb_off": "0x%x" % off,
                "root": _build_rb(r, off, fields)}

    order = (maple, rbtree) if _is_maple(kver) else (rbtree, maple)
    for build in order:
        t = build()
        if t is not None:
            return t
    return None


def _mm_diag(nodes):
    """Print why mm-offset discovery came up empty (called only when it did).

    For a few tasks, count the kheap pointers in the scan window and how many of
    them walk out to at least one VMA. If none do, VMA detection itself is off for
    this kernel (e.g. an unexpected vm_area_struct layout or address-range guess);
    if many do but no offset is consistent, the voting is the problem."""
    span = _MM_WIN
    print("[taskviz] mm-scan diagnostic (why mm_delta is n/a):")
    for node in nodes[:3]:
        try:
            buf = kmem.read_mem(node - span, 2 * span)
        except gdb.error as exc:
            print("  node 0x%x: window unreadable (%s)" % (node, exc))
            continue
        kheap = walkers = adj = 0
        hits = []
        for o in range(0, len(buf) - 8, 8):
            p = _child_addr(_u64(buf, o))
            if p is None:
                continue
            kheap += 1
            if _u64(buf, o) == _u64(buf, o + 8):
                adj += 1
            if len(hits) < 6 and _walk_vmas(p, budget=64):
                walkers += 1
                hits.append((o - span, p))
        print("  node 0x%x: %d kheap ptrs, %d adjacent-equal; VMA-walkable offsets: %s"
              % (node, kheap, adj,
                 ", ".join("%+#x->0x%x" % (d, p) for d, p in hits) or "none"))
    print("  (if 'none' everywhere, the vm_area_struct layout differs — send this "
          "output; otherwise re-run `taskviz sync`.)")


def _collect_vmas_for_node(node):
    """VMAs for the task whose tasks-list node is `node` (runs on gdb's thread).

    Returns the flat VMA list plus the reconstructed VMA container as a drawable
    tree — a maple tree on Linux ≥ 6.1, a red-black tree on older kernels — chosen
    from the auto-detected kernel version."""
    disc = _CACHE or {}
    mm_delta = disc.get("mm_delta")
    if mm_delta is None:
        return {"mm": None, "vmas": [], "error": "mm offset not resolved — sync first"}
    mm = kmem.rd_ptr_safe(node + mm_delta)
    if not kmem.is_kheap(mm):
        return {"mm": None, "vmas": [],
                "note": "no mm (kernel thread, or task exited)"}
    kver = disc.get("kver")
    # A maple kernel gets the dedicated tree walk (complete, no wandering); older
    # kernels use the generic BFS (which follows the mmap list / rb links).
    vmas = _maple_vmas(mm) if _is_maple(kver) else _walk_vmas(mm)
    out = {"mm": "0x%x" % mm, "vmas": vmas,
           "kver": kver["banner"] if kver else None,
           "vma_index": "maple" if _is_maple(kver) else ("rbtree" if kver else "?")}
    bases = [int(v["addr"], 16) for v in vmas]
    fields = {int(v["addr"], 16): v for v in vmas}
    tree = _vma_tree(mm, bases, fields, kver) if bases else None
    if tree is not None:
        out["tree"] = tree
    # A real user process has several VMAs; if a maple kernel yields very few, the
    # node walk is off — attach the raw maple bytes so the layout can be checked.
    if _is_maple(kver) and len(vmas) < 4:
        out["debug"] = _maple_debug(mm)
    return out


def _walk_tasks(anchor=None):
    global _CACHE
    disc = _CACHE
    if disc is not None:
        nxt = kmem.rd_ptr_safe(disc["tasks_head"])
        if not kmem.looks_like_name(kmem.read_cstr(nxt + disc["comm_delta"], 16)):
            disc = None
    if disc is None:
        disc = _discover(anchor)
        _CACHE = disc
    if disc is None:
        raise gdb.error(
            "could not locate the task list by memory scan. Be stopped IN THE "
            "KERNEL (p/x $pc should be 0xffffffff8...); if you are in userspace the "
            "kernel is not mapped in the current CR3 (KPTI), so kernel VAs can't be "
            "read — continue+interrupt until $pc is in the kernel, or break at a "
            "kernel address (see a 'kernel image' row in kvmmap). You can also pass "
            "a kernel address to anchor the scan: `taskviz sync 0x<kernel_addr>`")

    head, cd = disc["tasks_head"], disc["comm_delta"]
    nodes = [head]
    seen = set()
    node = kmem.rd_ptr_safe(head)
    while node and node != head and node not in seen and len(nodes) < 100000:
        seen.add(node)
        nodes.append(node)
        node = kmem.rd_ptr_safe(node)

    if "kver" not in disc:
        disc["kver"] = _detect_kernel_version(anchor)
    kver = disc["kver"]

    pid_delta = _find_pid_delta(nodes)
    mm_delta = disc.get("mm_delta")
    if mm_delta is None:
        mm_delta = _find_mm_delta(nodes)
        disc["mm_delta"] = mm_delta  # cache so /vmas need not rediscover
        if mm_delta is None:
            _mm_diag(nodes)
    tasks = []
    for node in nodes:
        pid = _u32(node + pid_delta) if pid_delta is not None else None
        has_mm = (mm_delta is not None
                  and kmem.is_kheap(kmem.rd_ptr_safe(node + mm_delta)))
        tasks.append({
            "pid": pid,
            "comm": kmem.read_cstr(node + cd, 16) or "",
            "node": "0x%x" % node,
            "mm": has_mm,
        })
    tasks.sort(key=lambda t: t["pid"] if t["pid"] is not None else (1 << 62))
    meta = {"comm_delta": cd, "pid_delta": pid_delta, "head": "0x%x" % head,
            "mm_delta": mm_delta,
            "kver": kver["banner"] if kver else None,
            "vma_index": "maple" if _is_maple(kver) else ("rbtree" if kver else "?")}
    return tasks, meta


def _task_sync(server, args=None):
    anchor = None
    for tok in (args or []):
        try:
            anchor = int(tok, 0)
            print("[taskviz] using scan anchor 0x%x" % anchor)
        except ValueError:
            print("[taskviz] ignoring invalid address '%s'" % tok)
    try:
        tasks, meta = _walk_tasks(anchor)
    except gdb.error as exc:
        server.state.set({"tasks": [], "meta": {}, "error": str(exc)})
        print("[taskviz] %s" % exc)
        return
    except Exception as exc:  # noqa: BLE001
        server.state.set({"tasks": [], "meta": {}, "error": "%s: %s" % (type(exc).__name__, exc)})
        print("[taskviz] error: %s" % exc)
        return
    server.state.set({"tasks": tasks, "meta": meta})
    print("[taskviz] kernel %s → VMA index: %s"
          % (meta["kver"] or "version unknown", meta["vma_index"]))
    print("[taskviz] synced %d tasks (comm_delta=%#x, pid_delta=%s, mm_delta=%s)"
          % (len(tasks), meta["comm_delta"],
             "n/a" if meta["pid_delta"] is None else "%#x" % meta["pid_delta"],
             "n/a" if meta["mm_delta"] is None else "%#x" % meta["mm_delta"]))


def _route_vmas(app, query):
    """On-demand: walk a task's mm to its vm_area_structs (like /proc/<pid>/maps),
    all from memory. Runs on gdb's main thread. Returns {ok, mm, vmas[...]}."""
    try:
        node = int(query.get("node", ["0"])[0], 0)
    except ValueError:
        return 400, json.dumps({"ok": False, "error": "bad node"}), "application/json"
    res = regviz_common.call_on_main(lambda: _collect_vmas_for_node(node))
    if not res.get("ok"):
        return 200, json.dumps({"ok": False, "error": res.get("error", "walk failed")}), \
            "application/json"
    return 200, json.dumps({"ok": True, **res["result"]}), "application/json"


regviz_common.install_app(
    prefix="taskviz",
    default_port=8776,
    label="task_struct",
    html_path=Path(__file__).resolve().parent / "task_viz.html",
    routes={"/vmas": _route_vmas},
    sync_fn=_task_sync,
    sync_hint="the process list (scans task_struct)",
)
