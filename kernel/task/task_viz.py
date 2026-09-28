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
_CACHE = None  # {tasks_head, comm_delta, mm_delta}

_MM_WIN = 0x2000           # bytes each side of a tasks node to scan for `mm`
_VMA_MAX = 4096            # BFS object budget when walking an mm's VMAs
_VMA_OBJ = 256             # bytes read per candidate object during the VMA walk
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
    later (offset 16 on modern kernels; a few words in on older ones). We anchor
    on vm_mm == mm, which is extremely specific, so we need not know the exact
    kernel version. vm_flags (r/w/x/shared) sits two words past vm_mm.
    """
    if buf is None:
        try:
            buf = kmem.read_mem(addr, 64)
        except gdb.error:
            return None
    start = _u64(buf, 0)
    end = _u64(buf, 8)
    if not (0 < start < end < _USER_TOP):
        return None
    if (start | end) & 0xFFF:
        return None
    mm_off = None
    for o in range(16, min(len(buf), 64) - 8, 8):
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
    and page-table pointers are not kheap object pointers, so they dead-end."""
    if not kmem.is_kheap(mm):
        return []
    vmas, visited = {}, set()
    try:
        queue = []
        head = kmem.read_mem(mm, 512)
        for o in range(0, len(head) - 8, 8):
            p = _u64(head, o)
            if kmem.is_kheap(p):
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
        v = _vma_at(obj, mm, buf[:64])
        if v is not None:
            vmas[obj] = v
        # Follow child/next pointers (maple-node slots, or vm_next on old kernels).
        for o in range(0, len(buf) - 8, 8):
            p = _u64(buf, o)
            if kmem.is_kheap(p) and p not in visited:
                queue.append(p)
    return sorted(vmas.values(), key=lambda x: int(x["start"], 16))


def _find_mm_delta(nodes):
    """Offset (relative to a tasks node) of the `mm` pointer, found heuristically.

    task_struct holds `struct mm_struct *mm, *active_mm;` adjacently, and for a
    user process the two are equal and point at the same kheap mm_struct (kernel
    threads have mm == NULL, so they simply do not vote). The right offset is the
    one where most tasks show that adjacent-equal-kheap pair AND the target really
    walks out to at least one VMA."""
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


def _collect_vmas_for_node(node):
    """VMAs for the task whose tasks-list node is `node` (runs on gdb's thread)."""
    disc = _CACHE
    mm_delta = disc.get("mm_delta") if disc else None
    if mm_delta is None:
        return {"mm": None, "vmas": [], "error": "mm offset not resolved — sync first"}
    mm = kmem.rd_ptr_safe(node + mm_delta)
    if not kmem.is_kheap(mm):
        return {"mm": None, "vmas": [],
                "note": "no mm (kernel thread, or task exited)"}
    return {"mm": "0x%x" % mm, "vmas": _walk_vmas(mm)}


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

    pid_delta = _find_pid_delta(nodes)
    mm_delta = disc.get("mm_delta")
    if mm_delta is None:
        mm_delta = _find_mm_delta(nodes)
        disc["mm_delta"] = mm_delta  # cache so /vmas need not rediscover
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
            "mm_delta": mm_delta}
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
