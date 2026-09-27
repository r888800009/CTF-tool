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
_CACHE = None  # {tasks_head, comm_delta}


def _u32(addr):
    try:
        return kmem.rd_uint(addr, 4)
    except gdb.error:
        return None


def _discover():
    """Locate init_task's `tasks` list head and the comm offset by scanning."""
    ps = kmem.ptr_size()
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
    """Offset (relative to a tasks node) of the `pid` field, found heuristically:
    pid and tgid are adjacent equal small ints for the group leaders on this
    list, and vary across tasks."""
    lo, hi = -1024, 1024
    wins = {}
    for node in nodes[:12]:
        try:
            wins[node] = kmem.read_mem(node + lo, hi - lo)
        except gdb.error:
            pass
    if not wins:
        return None
    for po in range(lo, hi - 8, 4):
        vals, good = [], 0
        for buf in wins.values():
            i = po - lo
            v = int.from_bytes(buf[i:i + 4], "little")
            v2 = int.from_bytes(buf[i + 4:i + 8], "little")
            vals.append(v)
            if v == v2 and 0 <= v < 0x400000:
                good += 1
        if good >= max(3, int(0.7 * len(wins))) and len(set(vals)) >= 3 and max(vals) > 0:
            return po
    return None


def _walk_tasks():
    global _CACHE
    disc = _CACHE
    if disc is not None:
        nxt = kmem.rd_ptr_safe(disc["tasks_head"])
        if not kmem.looks_like_name(kmem.read_cstr(nxt + disc["comm_delta"], 16)):
            disc = None
    if disc is None:
        disc = _discover()
        _CACHE = disc
    if disc is None:
        raise gdb.error(
            "could not locate the task list by memory scan — need to be stopped in "
            "the kernel (a kernel $pc or a kernel return address on the stack) on an "
            "x86-64 target")

    head, cd = disc["tasks_head"], disc["comm_delta"]
    nodes = [head]
    seen = set()
    node = kmem.rd_ptr_safe(head)
    while node and node != head and node not in seen and len(nodes) < 100000:
        seen.add(node)
        nodes.append(node)
        node = kmem.rd_ptr_safe(node)

    pid_delta = _find_pid_delta(nodes)
    tasks = []
    for node in nodes:
        pid = _u32(node + pid_delta) if pid_delta is not None else None
        tasks.append({
            "pid": pid,
            "comm": kmem.read_cstr(node + cd, 16) or "",
            "node": "0x%x" % node,
        })
    tasks.sort(key=lambda t: t["pid"] if t["pid"] is not None else (1 << 62))
    meta = {"comm_delta": cd, "pid_delta": pid_delta, "head": "0x%x" % head}
    return tasks, meta


def _task_sync(server, args=None):
    try:
        tasks, meta = _walk_tasks()
    except gdb.error as exc:
        server.state.set({"tasks": [], "meta": {}, "error": str(exc)})
        print("[taskviz] %s" % exc)
        return
    except Exception as exc:  # noqa: BLE001
        server.state.set({"tasks": [], "meta": {}, "error": "%s: %s" % (type(exc).__name__, exc)})
        print("[taskviz] error: %s" % exc)
        return
    server.state.set({"tasks": tasks, "meta": meta})
    print("[taskviz] synced %d tasks (comm_delta=%#x, pid_delta=%s)"
          % (len(tasks), meta["comm_delta"],
             "n/a" if meta["pid_delta"] is None else "%#x" % meta["pid_delta"]))


regviz_common.install_app(
    prefix="taskviz",
    default_port=8776,
    label="task_struct",
    html_path=Path(__file__).resolve().parent / "task_viz.html",
    sync_fn=_task_sync,
    sync_hint="the process list (scans task_struct)",
)
