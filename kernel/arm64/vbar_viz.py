"""ARM64 exception vector table viewer — a GDB plugin.

The AArch64 equivalent of the x86 IDT: `VBAR_EL1` points at a 2 KiB table of 16
entries (4 groups × 4 exception types), each a 0x80-byte block of *code* (not a
descriptor). This viewer reads VBAR_EL1 and, for each of the 16 vectors, shows its
address and the first few instructions, pulling out the handler each one branches
to — all from the gdb side, no kernel symbols required.

    (gdb) source kernel/arm64/vbar_viz.py
    (gdb) vbarviz sync

ARM64 has no vsyscall page (it uses a vDSO instead), so unlike the x86 idtviz this
viewer covers only the exception vector table. Shared server lives in
kernel/regviz_common.py.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import importlib  # noqa: E402
import regviz_common  # noqa: E402

importlib.reload(regviz_common)  # pick up edits to the shared module on re-source

import gdb  # noqa: E402  (provided by the gdb Python runtime)

# The 16 AArch64 exception vectors: 4 groups of 4, each entry 0x80 bytes apart.
_GROUPS = ["Current EL, SP0", "Current EL, SPx",
           "Lower EL, AArch64", "Lower EL, AArch32"]
_TYPES = ["Synchronous", "IRQ / vIRQ", "FIQ / vFIQ", "SError / vSError"]
_ENTRY = 0x80
_INSNS = 6  # instructions disassembled per vector entry

_BRANCH = re.compile(r"\b(?:bl?|br|b\.\w+)\b.*?(0x[0-9a-fA-F]+)")


def _read_sysreg(*names):
    """First readable value among candidate register expressions, or None."""
    for n in names:
        try:
            return int(gdb.parse_and_eval(n)) & 0xFFFFFFFFFFFFFFFF
        except gdb.error:
            continue
        except Exception:  # noqa: BLE001 - never let one bad read abort sync
            continue
    return None


def _disasm(addr, n=_INSNS):
    """Disassemble `n` instructions at `addr`; return (lines, first-branch-target).

    Runs on gdb's main thread (sync does), so gdb.execute is called directly."""
    try:
        out = gdb.execute("x/%di 0x%x" % (n, addr), from_tty=False, to_string=True) or ""
    except gdb.error:
        return [], None
    lines, target = [], None
    for raw in out.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        # Keep just the "mnemonic operands" part (after the address:\t), tidily.
        insn = raw.split("\t", 1)[1].strip() if "\t" in raw else raw
        lines.append(insn)
        if target is None:
            m = _BRANCH.search(insn)
            if m:
                target = m.group(1)
    return lines, target


def _vbar_sync(server, args=None):
    vbar = _read_sysreg("$VBAR_EL1", "$vbar_el1")
    if vbar is None:
        server.state.set({"error":
            "could not read VBAR_EL1 — this needs an AArch64 target whose gdb "
            "exposes system registers (e.g. a QEMU gdb stub). Are you on arm64?"})
        print("[vbarviz] VBAR_EL1 not readable — is this an arm64 target?")
        return
    cur = _read_sysreg("$CurrentEL")
    el = None if cur is None else (cur >> 2) & 0x3
    vectors = []
    for i in range(16):
        addr = vbar + i * _ENTRY
        asm, target = _disasm(addr)
        vectors.append({
            "index": i,
            "group": _GROUPS[i // 4],
            "type": _TYPES[i % 4],
            "addr": "0x%x" % addr,
            "asm": asm,
            "target": target,
        })
    server.state.set({
        "vbar": "0x%x" % vbar,
        "current_el": el,
        "vectors": vectors,
    })
    print("[vbarviz] synced exception vector table @ VBAR_EL1=0x%x (%d vectors%s)"
          % (vbar, len(vectors), "" if el is None else ", currently EL%d" % el))


regviz_common.install_app(
    prefix="vbarviz",
    default_port=8778,
    label="ARM64 vectors",
    html_path=Path(__file__).resolve().parent / "vbar_viz.html",
    sync_fn=_vbar_sync,
    sync_hint="the exception vector table (VBAR_EL1)",
)
