"""RISC-V control & status register (CSR) visualizer (GDB plugin).

Source this in gdb while debugging a RISC-V kernel through a QEMU gdb stub; it
starts the shared register web view and adds the `csrviz` command (`csrviz sync`).
See kernel/README.md. Shared logic lives in kernel/regviz_common.py; this file
only supplies the RISC-V CSR list.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import importlib  # noqa: E402
import regviz_common  # noqa: E402

importlib.reload(regviz_common)  # pick up edits to the shared module on re-source

regviz_common.install(
    prefix="csrviz",
    default_port=8772,
    directory=Path(__file__).resolve().parent,
    regs_js="csr_viz.regs.js",
    label="CSR",
    exprs=[
        ("mstatus", "$mstatus"),
        ("sstatus", "$sstatus"),
        ("misa", "$misa"),
        ("satp", "$satp"),
        ("mtvec", "$mtvec"),
        ("stvec", "$stvec"),
        ("mie", "$mie"),
        ("mip", "$mip"),
        ("sie", "$sie"),
        ("sip", "$sip"),
        ("mideleg", "$mideleg"),
        ("medeleg", "$medeleg"),
        ("mcause", "$mcause"),
        ("scause", "$scause"),
        ("mepc", "$mepc"),
        ("sepc", "$sepc"),
        ("mtval", "$mtval"),
        ("stval", "$stval"),
    ],
)
