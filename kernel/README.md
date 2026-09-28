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

There are also memory viewers built on the same server:

| Viewer | Folder | Source in gdb | Web command | Default port | Shows |
| --- | --- | --- | --- | --- | --- |
| SLUB slab caches | `kernel/slab/` | `source kernel/slab/slab_viz.py` | `slabviz` | 8774 | every `kmem_cache`: sizes, objs/slab, per-node slab/object counts |
| Kernel VM map | `kernel/kvmmap/` | `source kernel/kvmmap/kvmmap_viz.py` | `kvmmap` | 8775 | CR3 page tables coalesced into regions (VA/size/phys/perms/region) |
| Task list | `kernel/task/` | `source kernel/task/task_viz.py` | `taskviz` | 8776 | processes scanned from memory: PID, comm, tasks-node; expand to hexdump `task_struct` and follow `mm → vm_area_struct` (VMAs / maps) |

## Layout

The shared logic lives at `kernel/`, so each plugin stays tiny and free of
duplicated code (a jscpd pre-commit hook enforces this):

- `regviz_common.py` — a generic web-app server (`install_app`): the HTTP server,
  the `sync`/control commands, host binding and the reload logic. `install(...)`
  is a thin wrapper over it for the register views.
- `regviz.html` — the register page and its rendering engine (bit tables, hover
  tooltips, the page-table tree, polling).
- `regviz.css` — the shared dark theme, linked by every page.

Each architecture folder holds only:

- `<name>.py` — a thin plugin that lists its registers and calls
  `regviz_common.install(...)`.
- `<name>.regs.js` — the register schema (names, bit flags, multi-bit fields and
  decode hints) that the shared page renders. Served to the browser at `/regs.js`.

The slab viewer is a separate app on the same server: `kernel/slab/slab_viz.py`
walks `slab_caches` and calls `regviz_common.install_app(...)`, and
`kernel/slab/slab_viz.html` renders its table.

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
3. Each row shows its index, raw entry value, decoded flags
   (`P/RW/US/PWT/PCD/A/D/PS/G/NX`), the next-level physical base, and the
   (canonical) virtual address it covers. A `PS` entry at PDPT/PD is a
   1 GiB / 2 MiB large-page leaf; PT entries are 4 KiB leaves.
4. The **每張表顯示** number field takes any count of entries to show per table
   (1–512, typed in directly), and the **隱藏 not present** checkbox hides
   non-present entries — on
   by default, so you normally see only mapped entries; turn it off to inspect
   the whole page directory including empty slots.
5. Each table and entry has a small copy control that yields **paste-able gdb and
   WinDbg commands** for that step of the walk — e.g. `monitor xp/512gx <phys>`
   for gdb (QEMU), and `!dq <phys> L200` / `!pte <va>` for WinDbg. Each entry also
   has a **看 VA** button that copies a single clean QEMU-monitor command
   (`x /512gx 0x<va>`, no prefix or comments) to view the **virtual memory** that
   entry maps, straight in the HMP monitor (`x` reads virtual memory through the
   CPU's current page tables, unlike the physical `xp`).
6. Hovering any entry row shows a tooltip that **decodes every bit** of that
   entry — each flag's name, its live 0/1 value, and its description — plus the
   raw entry value and virtual address.

### Naming mode (Intel / Linux)

The x86_64 page has a **命名模式（縮寫）** selector that switches every mnemonic
between Intel's names (e.g. `PG`, `SMEP`, `NX`, `P`, `RW`) and the Linux kernel's
macro names (`X86_CR0_PG`, `X86_CR4_SMEP`, `EFER_NX`, `_PAGE_PRESENT`,
`_PAGE_RW`). It applies to the register bit tables, the page-table flags, **and
the page-table level names** — Intel `PML4 → PDPT → PD → PT` vs Linux
`PGD → PUD → PMD → PTE` — and the choice is remembered. Other arches can add their own modes by setting
`window.REGVIZ_MODES` and per-flag `alt` names in their `regs.js`.

This needs a **QEMU** target (the reads use the `xp` monitor command) and gdb
stopped at the prompt, since the reads are marshalled onto gdb's main thread. The
page-table walk is driven by an optional `window.REGVIZ_PAGETABLE` config in the
arch's `regs.js`, so other architectures can add their own walker later without
touching the shared engine.

## Slab viewer (Linux, SLUB)

`kernel/slab/slab_viz.py` shows the kernel's slab caches as a sortable, filterable
table — a richer `/proc/slabinfo` you can browse while stopped in gdb.

```gdb
(gdb) source kernel/slab/slab_viz.py
(gdb) slabviz sync                    # resolve slab_caches by symbol, then walk
(gdb) slabviz sync 0xffffffff82a4c0e0 # pure-memory mode: walk from a given address
```

**No symbols, no vmlinux, no guest access.** With no kernel symbols loaded,
`slabviz sync` discovers everything from memory on the gdb side alone (no root or
`/proc/kallsyms` in the guest needed): it anchors on a kernel `.text` address (the
current `$pc`, or a kernel return address found on the stack), reads the kernel
image to find the `"kmem_cache"` name string, locates a `.data` pointer to a heap
instance whose name field points at it (giving the `name` offset), and recovers
the `list` offset from that instance's ring links — then walks the ring. For this
you just need to be **stopped in the kernel** on an x86-64 SLUB target; the result
is cached. If auto-discovery can't get started, you can still pass the address
directly: `slabviz sync 0x<slab_caches>` (from the guest's `/proc/kallsyms` or
System.map if you happen to have them).

Each row is one `kmem_cache`: name, object size, allocated size, free-pointer
offset, objects per slab, page order, and the per-NUMA-node slab / object /
partial counts (summed across nodes). Click a column header to sort; type in the
box to filter by name. **Click a cache row to expand it** into a hexdump of that
`kmem_cache` struct (read live from kernel memory; adjust the byte count in the
detail row) — useful for eyeballing the struct's fields, especially in scan mode.

The list is walked **directly through memory**: only the address of the
`slab_caches` symbol is needed, and the ring is followed by reading each
`list_head.next` pointer, so traversal never depends on `struct kmem_cache`
being resolvable by name.

Two decode modes, chosen automatically (shown on the page):

- **debug info** — when the `struct kmem_cache` type is available (by name, or
  derived from a `struct kmem_cache *` global such as `kmem_cache`), every field
  is decoded.
- **memory scan** — with no usable type info, the layout is discovered by
  scanning: the `list` offset is recovered from a known cache instance (the
  `kmem_cache` global) that also sits on the ring, and the `name` offset is the
  first pointer field that resolves to a printable cache name across the caches
  (with a bounded brute-force fallback when no anchor symbol exists). This yields
  each cache's **name and address** even without DWARF.

Requirements: a Linux **SLUB** target (the kernel default) with at least the
`slab_caches` symbol. All reads are defensive, so a differing kernel shows what it
can and reports a clear error otherwise (e.g. on a non-kernel target).

## Kernel VM map (kvmmap)

`kernel/kvmmap/kvmmap_viz.py` is a `vmmap` for the kernel: it walks the current
`CR3`'s 4-level page tables and coalesces contiguous mappings with identical
permissions into regions.

```gdb
(gdb) source kernel/kvmmap/kvmmap_viz.py
(gdb) kvmmap sync
```

Mappings are collapsed **linearly** as the tree is walked: consecutive entries
that continue the same run are merged — either **contiguous** (VA and physical
both continue → one solid region) or a **repeat** (the same physical frame
reappearing at a regular VA stride, e.g. the vmemmap zero page → one `N × page`
row instead of N identical lines). Each row shows VA start/end, size (or
`N × page`), permissions (`r/w/x`, `u`ser vs `s`upervisor, `g`lobal) and a
**region label** — user, kernel image, modules, direct map, vmalloc, vmemmap or
vsyscall — coloured by area (pwntools-style). Rows in the **modules** region also
get a **module** column with the owning module's name, resolved best-effort by
scanning the kernel `modules` list from memory (needs kernel context; blank if it
can't be read). Sort by any column; filter by region, perms or module name. The 1 s poll carries only a small summary; the collapsed list is fetched
once per sync.

Like the slab viewer this is **pure memory, no symbols**: `CR3` is a register and
the page tables are read as physical memory over the QEMU monitor (`monitor xp`).
Targets x86-64 4-level paging; region boundaries follow
`Documentation/arch/x86/x86_64/mm.rst` and tolerate KASLR (the coarse windows are
fixed even though the bases move).

## Task list (task_struct)

`kernel/task/task_viz.py` scans the kernel's process list out of memory and shows
each task's PID and comm (name), like `ps`.

```gdb
(gdb) source kernel/task/task_viz.py
(gdb) taskviz sync
```

**Pure memory, no symbols, no guest access** — done entirely from the gdb side:
anchor on a kernel `.text` address (`$pc`, or a kernel return address on the
stack), read the kernel image, find init_task's `comm` string (`swapper/0`, in
`.data`), find its `tasks` list head beside it (a pair of kernel-heap pointers
whose comm-relative offset yields a printable name for the next task), then walk
the `tasks` ring reading each task's comm at that offset. The `pid` field offset is
discovered heuristically (pid == tgid, a small varied positive int for the group
leaders on the list). Needs to be stopped in the kernel on x86-64; the result is
cached. The `tasks node` column is a stable per-task anchor (`task_struct` base +
the `tasks` offset). Click a task row to hexdump its `task_struct` (region-coloured
pointers, adjustable offset/length).

Each expanded task also follows the chain **`task_struct → mm → vm_area_struct`**
and lists that process's VMAs, like `/proc/<pid>/maps` — again purely from memory.
The `mm` pointer offset is discovered by voting across tasks (a user process holds
adjacent, equal `mm`/`active_mm` kernel-heap pointers; kernel threads have
`mm == NULL` and simply do not vote and show no VMAs). From the `mm_struct` a
bounded memory BFS collects every `vm_area_struct`, anchored on the extremely
specific test that a VMA begins with an ascending, page-aligned `vm_start`/`vm_end`
pair in the user half and holds `vm_mm` pointing back at that `mm` — the `vm_mm`
member is located by scanning the VMA head, so both the 6.1+ maple-tree layout
(`vm_mm` right after the range) and the older red-black-tree layout (`vm_mm` after
`vm_next`/`vm_prev`/`vm_rb`) are handled. `vm_flags` is decoded into `r/w/x` plus
`p`/`s` (private/shared). Container pointers are un-tagged before dereferencing:
the maple tree encodes a node's type in the low byte of each internal-node pointer
(`node | (type << 3) | 2`, 256-byte aligned), so those are masked with `~0xff`
while ordinary 8-aligned pointers use `~0x7`.

**The kernel version is auto-detected** (from the `Linux version …` banner in the
image, no symbols needed) and drives which VMA index the viewer reconstructs and
**draws**:

- **Linux ≥ 6.1 → the maple tree.** From `mm_mt.ma_root` it walks the maple nodes
  directly: each enode's low byte gives the node type, and only that type's slot
  array is followed (leaf_64/range_64: 16 slots at offset 128; arange_64: 10 slots
  at 80) — child enodes recurse, leaf slots hold the stored `vm_area_struct`
  pointers. Walking only the tree's own slots (rather than scanning the whole node
  or wandering the heap) is what makes the walk both complete and bounded. The
  n-ary node-link tree is drawn with the leaf VMA ranges as chips.
- **Older kernels → the red-black tree (`mm_rb`).** It finds the embedded `vm_rb`
  offset (the word triple whose children/parent reference other VMAs' rb_nodes),
  locates the root from `mm_rb.rb_node`, and walks the parent-colour/left/right
  links into a red/black binary tree.

If the version can't be read, both are attempted. The VMAs and the tree for a row
are fetched on demand (the `/vmas` endpoint) when you expand it; when mm-offset
discovery fails, `sync` prints a diagnostic explaining why.

The page also has a **task_struct decoder**: paste a hexdump (or pull one from a
node address with the read button) and decode named fields at adjustable offsets
(`u8/16/32/64`, signed, `ptr` — coloured by region — and `str`). "用偵測到的
offset 預填" seeds `comm`/`pid`/`tgid` from the offsets the sync discovered, so you
can read one task's fields and tweak from there.

## Shared helpers

`kernel/kmem.py` holds the pure-memory toolkit shared by the slab and task viewers
— the kernel-`.text` anchor, kernel-image scan, symbol lookup, C-string reads and
address-region tests — so no viewer re-implements them.

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
