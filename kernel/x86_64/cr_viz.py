"""x86_64 control-register visualizer (GDB plugin).

Source this in gdb (typically while debugging an x86_64 kernel through a QEMU gdb
stub); it starts the shared register web view and adds the `crviz` command (run
`crviz sync` to push values). See kernel/README.md for details. Heavy lifting in
kernel/regviz_common.py; this file only supplies the x86_64 register list.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import importlib  # noqa: E402
import regviz_common  # noqa: E402

importlib.reload(regviz_common)  # pick up edits to the shared module on re-source

regviz_common.install(
    prefix="crviz",
    default_port=8770,
    directory=Path(__file__).resolve().parent,
    regs_js="cr_viz.regs.js",
    label="control-register",
    exprs=[
        ("CR0", "$cr0"),
        ("CR2", "$cr2"),
        ("CR3", "$cr3"),
        ("CR4", "$cr4"),
        ("CR8", "$cr8"),
        ("EFER", "$efer"),
    ],
)
