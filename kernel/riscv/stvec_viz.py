"""RISC-V supervisor trap-vector viewer — a GDB plugin.

The RISC-V counterpart of the x86 IDT / ARM64 VBAR: Linux runs in S-mode, whose
trap entry point is the `stvec` CSR. `stvec` packs a BASE address and a MODE:

  * MODE 0 (Direct)   — every trap (exception and interrupt) enters at BASE;
  * MODE 1 (Vectored) — exceptions enter at BASE, but interrupt `cause` enters at
    BASE + 4 × cause (a small jump table).

This viewer reads `stvec`, shows BASE/MODE, and disassembles the trap handler(s) —
the single BASE handler in Direct mode, plus the per-interrupt vector slots in
Vectored mode — pulling out the handler each slot jumps to. Purely from the gdb
side, no kernel symbols.

    (gdb) source kernel/riscv/stvec_viz.py
    (gdb) stvecviz sync

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

_INSNS = 6  # instructions disassembled per handler slot
# RISC-V control-transfer mnemonics whose operand reveals a handler address.
_BRANCH = re.compile(r"\b(?:jal|j|call|tail|b\w+)\b[^,]*?(0x[0-9a-fA-F]+)")

# Standard S-mode interrupt causes (used for the Vectored-mode jump table).
_INT_CAUSES = {
    1: "supervisor software",
    5: "supervisor timer",
    9: "supervisor external",
}


def _read_csr(*names):
    for n in names:
        try:
            return int(gdb.parse_and_eval(n)) & 0xFFFFFFFFFFFFFFFF
        except gdb.error:
            continue
        except Exception:  # noqa: BLE001
            continue
    return None


def _disasm(addr, n=_INSNS):
    """Disassemble `n` instructions at `addr`; return (lines, first-jump-target)."""
    try:
        out = gdb.execute("x/%di 0x%x" % (n, addr), from_tty=False, to_string=True) or ""
    except gdb.error:
        return [], None
    lines, target = [], None
    for raw in out.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        insn = raw.split("\t", 1)[1].strip() if "\t" in raw else raw
        lines.append(insn)
        if target is None:
            m = _BRANCH.search(insn)
            if m:
                target = m.group(1)
    return lines, target


def _entry(name, addr, cause=None):
    asm, target = _disasm(addr)
    return {"name": name, "cause": cause, "addr": "0x%x" % addr,
            "asm": asm, "target": target}


def _stvec_sync(server, args=None):
    stvec = _read_csr("$stvec")
    if stvec is None:
        server.state.set({"error":
            "could not read the `stvec` CSR — this needs a RISC-V target whose gdb "
            "exposes CSRs (e.g. a QEMU gdb stub). Are you on riscv?"})
        print("[stvecviz] stvec not readable — is this a riscv target?")
        return
    base = stvec & ~0x3
    mode = stvec & 0x3
    mode_name = {0: "Direct", 1: "Vectored"}.get(mode, "reserved(%d)" % mode)
    entries = []
    if mode == 1:
        entries.append(_entry("exceptions → BASE", base))
        for cause, label in sorted(_INT_CAUSES.items()):
            entries.append(_entry("IRQ: %s" % label, base + 4 * cause, cause))
    else:
        entries.append(_entry("all traps (Direct)", base))
    server.state.set({
        "stvec": "0x%x" % stvec, "base": "0x%x" % base,
        "mode": mode, "mode_name": mode_name,
        "scause": _fmt(_read_csr("$scause")), "sepc": _fmt(_read_csr("$sepc")),
        "entries": entries,
    })
    print("[stvecviz] synced stvec=0x%x (BASE=0x%x, MODE=%s, %d handler slot%s)"
          % (stvec, base, mode_name, len(entries), "" if len(entries) == 1 else "s"))


def _fmt(v):
    return None if v is None else "0x%x" % v


regviz_common.install_app(
    prefix="stvecviz",
    default_port=8779,
    label="RISC-V trap vector",
    html_path=Path(__file__).resolve().parent / "stvec_viz.html",
    sync_fn=_stvec_sync,
    sync_hint="the supervisor trap vector (stvec)",
)
