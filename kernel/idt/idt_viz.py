"""x86-64 interrupt descriptor table (IDT) + vsyscall viewer — a GDB plugin.

Shows the CPU's live interrupt vector table and the vsyscall page in the browser,
purely from the gdb/QEMU side with no kernel symbols:

  * the IDT base/limit come from the QEMU monitor (`monitor info registers` prints
    `IDT= <base> <limit>`), which is the authoritative IDTR — no symbols needed;
  * the table (up to 256 × 16-byte gate descriptors) is read from that base as
    kernel virtual memory and each gate decoded: handler address, gate type
    (interrupt/trap), DPL, IST index, present bit, and the standard exception name
    for vectors 0–31;
  * the three vsyscall entries (gettimeofday/time/getcpu at 0xffffffffff600000 +
    0/0x400/0x800) are read and shown; on kernels with vsyscall emulated or off the
    page is unreadable, which the page reports.

    (gdb) source kernel/idt/idt_viz.py
    (gdb) idtviz sync

Targets x86-64 with a QEMU gdb stub (the monitor is required for the IDTR).
Shared server lives in kernel/regviz_common.py.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import importlib  # noqa: E402
import regviz_common  # noqa: E402

importlib.reload(regviz_common)  # pick up edits to the shared module on re-source

import gdb  # noqa: E402  (provided by the gdb Python runtime)

# Architecturally-defined x86-64 exception vectors (0–31); the rest are
# device/IPI/user vectors that have no fixed mnemonic.
_VEC_NAMES = {
    0: "#DE divide error", 1: "#DB debug", 2: "NMI", 3: "#BP breakpoint",
    4: "#OF overflow", 5: "#BR bound range", 6: "#UD invalid opcode",
    7: "#NM device N/A", 8: "#DF double fault", 9: "coproc seg overrun",
    10: "#TS invalid TSS", 11: "#NP segment N/P", 12: "#SS stack fault",
    13: "#GP general protection", 14: "#PF page fault", 15: "(reserved)",
    16: "#MF x87 FP", 17: "#AC alignment check", 18: "#MC machine check",
    19: "#XM SIMD FP", 20: "#VE virtualization", 21: "#CP control prot.",
    28: "#HV hypervisor inj.", 29: "#VC VMM comm.", 30: "#SX security",
    0x80: "int 0x80 (legacy syscall)",
}
# Gate type nibble (bits 0–3 of the type/attr byte) on x86-64.
_GATE_TYPES = {0x5: "task", 0xC: "call", 0xE: "interrupt", 0xF: "trap"}

_IDT_MAX = 256 * 16  # a full IDT is 256 gates × 16 bytes

_VSYSCALL = [
    ("gettimeofday", 0xFFFFFFFFFF600000),
    ("time",         0xFFFFFFFFFF600400),
    ("getcpu",       0xFFFFFFFFFF600800),
]


def _parse_dtr(name, text):
    """Parse a descriptor-table register line (`IDT= <base> <limit>` /
    `GDT= …`) from `monitor info registers`. Returns (base, limit) or (None, None)."""
    m = re.search(r"^%s\s*=\s*([0-9a-fA-F]+)\s+([0-9a-fA-F]+)" % name, text, re.M)
    if not m:
        return None, None
    return int(m.group(1), 16), int(m.group(2), 16)


def _read_virt(addr, count):
    """Read `count` bytes of virtual memory, or None. `sync` already runs on gdb's
    main thread, so call the API directly — marshalling via post_event here would
    deadlock (the main thread would be blocked waiting for its own event)."""
    try:
        return bytes(gdb.selected_inferior().read_memory(addr, count))
    except gdb.error:
        return None


def _decode_idt(data):
    """Decode a block of 16-byte x86-64 gate descriptors into rows."""
    gates = []
    for i in range(len(data) // 16):
        b = data[i * 16:i * 16 + 16]
        off_lo = int.from_bytes(b[0:2], "little")
        sel = int.from_bytes(b[2:4], "little")
        ist = b[4] & 0x7
        ta = b[5]
        off_mid = int.from_bytes(b[6:8], "little")
        off_hi = int.from_bytes(b[8:12], "little")
        handler = off_lo | (off_mid << 16) | (off_hi << 32)
        gates.append({
            "vec": i,
            "name": _VEC_NAMES.get(i, ""),
            "handler": "0x%x" % handler,
            "type": _GATE_TYPES.get(ta & 0xF, "0x%x" % (ta & 0xF)),
            "dpl": (ta >> 5) & 0x3,
            "ist": ist,
            "present": bool((ta >> 7) & 1),
            "sel": "0x%x" % sel,
        })
    return gates


def _read_vsyscall():
    """Read the three vsyscall entry stubs; unreadable → emulated/disabled."""
    out = []
    for name, addr in _VSYSCALL:
        data = _read_virt(addr, 32)
        row = {"name": name, "addr": "0x%x" % addr}
        if data is None:
            row["readable"] = False
        else:
            row["readable"] = True
            row["hex"] = data.hex()
        out.append(row)
    return out


def _idt_sync(server, args=None):
    # `sync` runs on gdb's main thread, so call gdb directly (no post_event, which
    # would deadlock waiting for the main thread that is blocked here).
    try:
        text = gdb.execute("monitor info registers", from_tty=False, to_string=True) or ""
    except gdb.error as exc:
        server.state.set({"error":
            "could not read the IDTR via `monitor info registers` (%s) — this needs "
            "a QEMU gdb stub with a monitor" % exc})
        print("[idtviz] %s" % exc)
        return
    base, limit = _parse_dtr("IDT", text)
    if base is None:
        server.state.set({"error": "no `IDT=` line in `monitor info registers` output"})
        print("[idtviz] could not find the IDT register in the monitor output")
        return
    count = min(((limit + 1) // 16) * 16, _IDT_MAX)
    data = _read_virt(base, count) if count else None
    if not data:
        server.state.set({
            "idt_base": "0x%x" % base, "idt_limit": limit, "gates": [],
            "vsyscall": _read_vsyscall(),
            "error": "IDT base 0x%x is not readable — be stopped in the kernel "
                     "(the IDT is in the CPU entry area)" % base})
        print("[idtviz] IDT base 0x%x unreadable" % base)
        return
    gates = _decode_idt(data)
    gbase, glimit = _parse_dtr("GDT", text)
    server.state.set({
        "idt_base": "0x%x" % base, "idt_limit": limit,
        "gdt_base": None if gbase is None else "0x%x" % gbase, "gdt_limit": glimit,
        "gates": gates, "vsyscall": _read_vsyscall(),
    })
    present = sum(1 for g in gates if g["present"])
    print("[idtviz] synced IDT @ 0x%x (%d gates, %d present) + vsyscall"
          % (base, len(gates), present))


regviz_common.install_app(
    prefix="idtviz",
    default_port=8777,
    label="IDT / vsyscall",
    html_path=Path(__file__).resolve().parent / "idt_viz.html",
    sync_fn=_idt_sync,
    sync_hint="the interrupt vector table and vsyscall",
)
