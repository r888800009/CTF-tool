"""AArch64 (ARM64) system-register visualizer (GDB plugin).

Source this in gdb while debugging an aarch64 kernel through a QEMU gdb stub; it
starts the shared register web view and adds the `armviz` and `sync` commands.
See kernel/README.md. Shared logic lives in kernel/regviz_common.py; this file
only supplies the AArch64 register list.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import regviz_common  # noqa: E402

regviz_common.install(
    prefix="armviz",
    default_port=8771,
    directory=Path(__file__).resolve().parent,
    regs_js="sysreg_viz.regs.js",
    label="system-register",
    exprs=[
        ("SCTLR_EL1", "$SCTLR_EL1"),
        ("TCR_EL1", "$TCR_EL1"),
        ("TTBR0_EL1", "$TTBR0_EL1"),
        ("TTBR1_EL1", "$TTBR1_EL1"),
        ("MAIR_EL1", "$MAIR_EL1"),
        ("ESR_EL1", "$ESR_EL1"),
        ("FAR_EL1", "$FAR_EL1"),
        ("VBAR_EL1", "$VBAR_EL1"),
        ("CPACR_EL1", "$CPACR_EL1"),
        ("CurrentEL", "$CurrentEL"),
        # DAIF is often not a plainly-named register; try the PSTATE views too.
        ("DAIF", ["$DAIF", "$pstate", "$cpsr"]),
        ("SPSR_EL1", "$SPSR_EL1"),
        ("ELR_EL1", "$ELR_EL1"),
    ],
)
