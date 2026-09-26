"""MIPS CP0 (coprocessor 0) register visualizer (GDB plugin).

Source this in gdb while debugging a MIPS kernel through a QEMU gdb stub; it
starts the shared register web view and adds the `cp0viz` and `sync` commands.
See kernel/README.md. Shared logic lives in kernel/regviz_common.py; this file
only supplies the CP0 register list.

gdb's names for CP0 registers vary by target, so each register lists several
candidate expressions (tried in order) rather than one fixed name.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import regviz_common  # noqa: E402

regviz_common.install(
    prefix="cp0viz",
    default_port=8773,
    directory=Path(__file__).resolve().parent,
    regs_js="cp0_viz.regs.js",
    label="CP0-register",
    exprs=[
        ("Status", ["$status", "$Status", "$12"]),
        ("Cause", ["$cause", "$Cause", "$13"]),
        ("EPC", ["$epc", "$EPC", "$14"]),
        ("BadVAddr", ["$badvaddr", "$BadVAddr", "$8"]),
        ("EntryHi", ["$entryhi", "$EntryHi", "$10"]),
        ("EntryLo0", ["$entrylo0", "$EntryLo0", "$2"]),
        ("EntryLo1", ["$entrylo1", "$EntryLo1", "$3"]),
        ("PageMask", ["$pagemask", "$PageMask", "$5"]),
        ("Index", ["$index", "$Index", "$0"]),
        ("Random", ["$random", "$Random", "$1"]),
        ("Wired", ["$wired", "$Wired", "$6"]),
        ("Context", ["$context", "$Context", "$4"]),
        ("Config", ["$config", "$Config", "$16"]),
    ],
)
