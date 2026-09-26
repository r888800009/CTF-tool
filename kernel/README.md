# Kernel Register Visualizers

GDB plugins that render a CPU's control / system registers as **interactive bit
tables** in your browser. Hover any bit to see its decoded state (SET / clear),
a short description, and the whole register value. The page only updates when you
explicitly run the `<viz> sync` subcommand in gdb — nothing is read from the
target automatically.

These are meant for debugging a kernel through a live gdb stub (typically QEMU
`-s -S`) where you want to eyeball paging mode, privilege state, fault
addresses, interrupt masks, and so on.

## Architectures

| Arch | Folder | Source in gdb | Web command | Default port | Registers |
| --- | --- | --- | --- | --- | --- |
| x86_64 | `kernel/x86_64/` | `source kernel/x86_64/cr_viz.py` | `crviz` | 8770 | CR0/CR2/CR3/CR4/CR8, EFER |
| AArch64 (ARM64) | `kernel/arm64/` | `source kernel/arm64/sysreg_viz.py` | `armviz` | 8771 | SCTLR/TCR/TTBR0/1/MAIR/ESR/FAR/VBAR/CPACR/DAIF/CurrentEL … |
| RISC-V | `kernel/riscv/` | `source kernel/riscv/csr_viz.py` | `csrviz` | 8772 | mstatus/sstatus/misa/satp/mtvec/mie/mip/mcause … |
| MIPS | `kernel/mips/` | `source kernel/mips/cp0_viz.py` | `cp0viz` | 8773 | Status/Cause/EPC/BadVAddr/EntryHi/EntryLo/PageMask … |

All four plugins behave the same way and share the same UI.

## Layout

The shared logic lives in two files at `kernel/`, so the per-arch plugins stay
tiny and free of duplicated code (a jscpd pre-commit hook enforces this):

- `regviz_common.py` — the web server, the `sync`/control commands, the reload
  logic and the defensive register reading.
- `regviz.html` — the single web page and its rendering engine (bit tables,
  hover tooltips, polling).

Each architecture folder holds only:

- `<name>.py` — a thin plugin that lists its registers and calls
  `regviz_common.install(...)`.
- `<name>.regs.js` — the register schema (names, bit flags, multi-bit fields and
  decode hints) that the shared page renders. Served to the browser at `/regs.js`.

## Usage

Pick the plugin for your target and `source` it from the repository root (paths
are relative to the repo):

```gdb
(gdb) source kernel/x86_64/cr_viz.py      # or arm64/sysreg_viz.py, riscv/csr_viz.py, mips/cp0_viz.py
```

Sourcing the file:

- starts a small local web server (see the port in the table above),
- opens the page in your browser (skipped silently on headless machines — just
  open the printed URL yourself),
- registers a single per-arch command (`crviz` / `armviz` / `csrviz` / `cp0viz`)
  with subcommands.

Then, whenever execution stops and you want to inspect the registers, run the
`sync` subcommand of that command (x86_64 shown here):

```gdb
(gdb) crviz sync      # or armviz sync / csrviz sync / cp0viz sync
```

The page reflects the new values within a second. `<viz> sync` is the *only* thing
that reads registers, so the view always shows a snapshot you asked for.

## Commands

Each plugin registers one command, named per arch — `crviz` / `armviz` / `csrviz`
/ `cp0viz`, shown here as `<viz>`. There is no bare global `sync`; it is a
subcommand so it never collides with anything else in your gdb session.

| Command | Description |
| --- | --- |
| `<viz> sync` | Read the registers now and push them to the web page. |
| `<viz>` / `<viz> status` | Show whether the server is running and the last sync time. |
| `<viz> start [HOST] [PORT]` | Start the server, optionally on a specific bind address and/or port. |
| `<viz> stop` | Stop the server. |

## Access from another machine

By default the server binds to `127.0.0.1` (loopback only). When gdb runs on one
machine and you want to open the page from another, bind to all interfaces by
passing the host to the start command — it is **not** a default, you opt in:

```gdb
(gdb) crviz start 0.0.0.0            # x86_64; use armviz / csrviz / cp0viz for the others
(gdb) crviz start 0.0.0.0 8080       # all interfaces, custom port
(gdb) crviz start 0.0.0.0:8080       # host:port form also works
```

When bound to `0.0.0.0` the plugin prints a URL using this machine's LAN IP so a
remote browser has a reachable address to open. Only bind to `0.0.0.0` on a
network you trust — anyone who can reach the port can view the register snapshot.

## Page tables (x86_64)

The x86_64 page shows an extra **Page tables** section that walks the 4-level
paging hierarchy live from `CR3`:

1. Run `crviz sync` so the page has the current `CR3`.
2. The tree shows the `PML4` root; click a node to expand it one level at a time
   (`PML4 → PDPT → PD → PT`). Each expansion reads the pointed-to table (512
   8-byte entries) over the gdb/QEMU monitor (`monitor xp`).
3. Only *present* entries are listed; each row shows its index, raw entry value,
   decoded flags (`P/RW/US/PWT/PCD/A/D/PS/G/NX`), the next-level physical base,
   and the (canonical) virtual address it covers. A `PS` entry at PDPT/PD is a
   1 GiB / 2 MiB large-page leaf; PT entries are 4 KiB leaves.

This needs a **QEMU** target (the reads use the `xp` monitor command) and gdb
stopped at the prompt, since the reads are marshalled onto gdb's main thread. The
page-table walk is driven by an optional `window.REGVIZ_PAGETABLE` config in the
arch's `regs.js`, so other architectures can add their own walker later without
touching the shared engine.

## Notes

- Control / system registers are only exposed by gdb when attached to a **live
  target** (for example a QEMU gdb stub started with `-s -S`). On a plain
  user-space process the reads fail and the page shows `n/a` for every register —
  this is expected.
- Every register is read defensively via `gdb.parse_and_eval`; ones the target
  does not expose simply show `n/a` instead of aborting the sync. On MIPS the CP0
  register names vary by target, so several name aliases are tried per register.
- Register values are sent to the browser as hex strings and decoded with
  `BigInt`, so 64-bit values keep full precision.
- The default ports differ per arch, so you can run more than one at a time; use
  `<viz> start PORT` to override if a port is taken.

## Typical QEMU setup

```sh
# x86_64 example — same idea for the other arches with the matching qemu-system-*.
qemu-system-x86_64 -s -S -kernel <your-kernel> ...   # -s = gdb stub on :1234, -S = pause at start
gdb -ex 'target remote :1234' -ex 'source kernel/x86_64/cr_viz.py'
# ... set breakpoints, continue, then when stopped:
(gdb) crviz sync
```
