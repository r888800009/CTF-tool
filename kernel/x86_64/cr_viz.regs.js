// x86_64 control-register schema, consumed by the shared regviz.html engine.
// Each entry: {name, desc, width?, addr?, flags?, fields?, decode?}.
//   flags : { bit: [mnemonic, description, alt?] }  where alt maps a naming-mode
//           key -> alternate mnemonic, e.g. {linux: "X86_CR0_PG"}.
//   fields: [ {hi, lo, mn, desc, map?, alt?} ].
// window.REGVIZ_MODES defines the naming-mode menu; the base name (mnemonic) is
// used whenever the selected mode has no alt entry, so "intel" needs no alts.
window.REGVIZ_TITLE = "x86_64 Control Registers";
window.REGVIZ_MODES = [
  { key: "intel", label: "Intel" },
  { key: "linux", label: "Linux" },
];
window.REGS = [
  {
    name: "CR0", width: 32,
    desc: "System control flags: protection, paging and the FPU/cache mode.",
    flags: {
      0:  ["PE", "Protection Enable — 1 = protected mode.", { linux: "X86_CR0_PE" }],
      1:  ["MP", "Monitor Coprocessor — controls WAIT/FWAIT with TS.", { linux: "X86_CR0_MP" }],
      2:  ["EM", "Emulation — 1 = no x87 FPU present, x87 traps.", { linux: "X86_CR0_EM" }],
      3:  ["TS", "Task Switched — set on task switch to lazily save FPU state.", { linux: "X86_CR0_TS" }],
      4:  ["ET", "Extension Type — reserved as 1 on modern CPUs.", { linux: "X86_CR0_ET" }],
      5:  ["NE", "Numeric Error — 1 = native x87 error reporting (#MF).", { linux: "X86_CR0_NE" }],
      16: ["WP", "Write Protect — 1 = supervisor cannot write read-only pages.", { linux: "X86_CR0_WP" }],
      18: ["AM", "Alignment Mask — enables #AC alignment checks with EFLAGS.AC.", { linux: "X86_CR0_AM" }],
      29: ["NW", "Not Write-through — legacy cache write policy.", { linux: "X86_CR0_NW" }],
      30: ["CD", "Cache Disable — 1 = caching disabled.", { linux: "X86_CR0_CD" }],
      31: ["PG", "Paging — 1 = paging enabled (requires PE).", { linux: "X86_CR0_PG" }],
    },
  },
  {
    name: "CR4", width: 32,
    desc: "Feature enable flags: PAE, page-global, SMEP/SMAP, VMX and more.",
    flags: {
      0:  ["VME", "Virtual-8086 Mode Extensions.", { linux: "X86_CR4_VME" }],
      1:  ["PVI", "Protected-Mode Virtual Interrupts.", { linux: "X86_CR4_PVI" }],
      2:  ["TSD", "Time Stamp Disable — RDTSC restricted to ring 0.", { linux: "X86_CR4_TSD" }],
      3:  ["DE", "Debugging Extensions.", { linux: "X86_CR4_DE" }],
      4:  ["PSE", "Page Size Extensions — enables 4 MiB pages (32-bit paging).", { linux: "X86_CR4_PSE" }],
      5:  ["PAE", "Physical Address Extension — required for long mode.", { linux: "X86_CR4_PAE" }],
      6:  ["MCE", "Machine-Check Enable.", { linux: "X86_CR4_MCE" }],
      7:  ["PGE", "Page Global Enable — global TLB entries survive CR3 loads.", { linux: "X86_CR4_PGE" }],
      8:  ["PCE", "Performance-Counter Enable for RDPMC.", { linux: "X86_CR4_PCE" }],
      9:  ["OSFXSR", "OS support for FXSAVE/FXRSTOR and SSE.", { linux: "X86_CR4_OSFXSR" }],
      10: ["OSXMMEXCPT", "OS support for unmasked SIMD FP exceptions (#XM).", { linux: "X86_CR4_OSXMMEXCPT" }],
      11: ["UMIP", "User-Mode Instruction Prevention (SGDT/SIDT/etc.).", { linux: "X86_CR4_UMIP" }],
      12: ["LA57", "5-level paging (57-bit linear addresses).", { linux: "X86_CR4_LA57" }],
      13: ["VMXE", "VMX Enable.", { linux: "X86_CR4_VMXE" }],
      14: ["SMXE", "SMX Enable.", { linux: "X86_CR4_SMXE" }],
      16: ["FSGSBASE", "Enables RD/WR FS/GS BASE instructions.", { linux: "X86_CR4_FSGSBASE" }],
      17: ["PCIDE", "Process-Context Identifiers Enable.", { linux: "X86_CR4_PCIDE" }],
      18: ["OSXSAVE", "XSAVE and processor extended states enable.", { linux: "X86_CR4_OSXSAVE" }],
      19: ["KL", "Key Locker Enable.", { linux: "X86_CR4_KL" }],
      20: ["SMEP", "Supervisor Mode Execution Prevention.", { linux: "X86_CR4_SMEP" }],
      21: ["SMAP", "Supervisor Mode Access Prevention.", { linux: "X86_CR4_SMAP" }],
      22: ["PKE", "Protection Keys for user pages (PKU).", { linux: "X86_CR4_PKE" }],
      23: ["CET", "Control-flow Enforcement Technology.", { linux: "X86_CR4_CET" }],
      24: ["PKS", "Protection Keys for supervisor pages.", { linux: "X86_CR4_PKS" }],
    },
  },
  {
    name: "EFER", width: 16,
    desc: "Extended Feature Enable MSR (0xC0000080) — long mode, NX, SYSCALL.",
    flags: {
      0:  ["SCE", "System Call Extensions — enables SYSCALL/SYSRET.", { linux: "EFER_SCE" }],
      8:  ["LME", "Long Mode Enable.", { linux: "EFER_LME" }],
      10: ["LMA", "Long Mode Active (read-only status).", { linux: "EFER_LMA" }],
      11: ["NXE", "No-Execute Enable — enables the NX page bit.", { linux: "EFER_NX" }],
      12: ["SVME", "Secure Virtual Machine Enable (AMD-V).", { linux: "EFER_SVME" }],
      13: ["LMSLE", "Long Mode Segment Limit Enable (AMD).", { linux: "EFER_LMSLE" }],
      14: ["FFXSR", "Fast FXSAVE/FXRSTOR.", { linux: "EFER_FFXSR" }],
      15: ["TCE", "Translation Cache Extension.", { linux: "EFER_TCE" }],
    },
  },
  {
    name: "CR3", addr: true,
    desc: "Top-level paging structure base (PML4/PML5). Low bits hold flags or PCID.",
    decode: (v) => [
      ["Base (PML4 phys)", "0x" + (v & ~0xFFFn & ((1n << 52n) - 1n)).toString(16)],
      ["Low 12 bits (PCID / flags)", "0x" + (v & 0xFFFn).toString(16)],
      ["PWT (bit 3)", String((v >> 3n) & 1n)],
      ["PCD (bit 4)", String((v >> 4n) & 1n)],
    ],
  },
  {
    name: "CR2", addr: true,
    desc: "Linear address that triggered the most recent page fault (#PF).",
  },
  {
    name: "CR8", width: 8,
    desc: "Task Priority Register — bits 0-3 gate interrupt delivery by priority class.",
    fields: [{ hi: 3, lo: 0, mn: "TPR", desc: "Task priority class (0-15)." }],
    decode: (v) => [["TPR (task priority)", String(v & 0xFn)]],
  },
];

// Paging tree, walked live from CR3 via the shared page-table engine. Enables the
// "Page tables" section: click a node to read the pointed-to table (512 8-byte
// entries) over the gdb/QEMU monitor and expand the next level.
//
// The depth is chosen at render time from CR4.LA57 (bit 12): 4-level, or 5-level
// (LA57) as used by many syzkaller/syzbot kernels. Only the number of levels and
// the canonical sign-extend boundary change; everything below is shared. Falls
// back to 4-level before CR4 has been synced.
window.REGVIZ_PAGETABLE = {
  title: "x86-64 paging  (CR3 → page tables)",
  baseReg: "CR3",                    // root table base comes from this register
  baseMask: "0x000ffffffffff000",    // physical base = bits 12..51 of an entry
  presentBit: 0,                     // bit 0 = Present
  largePageBit: 7,                   // bit 7 = PS: a leaf 1 GiB (PDPT) / 2 MiB (PD) page
  entriesPerTable: 512,
  modeReg: "CR4",                    // depth selector: CR4.LA57 (bit 12)
  modeBit: 12,
  defaultDepth: "4",
  // Level names follow the naming mode too: Intel PMLx/PDPT/PD/PT vs Linux
  // PGD/P4D/PUD/PMD/PTE. In 4-level paging the P4D level is folded away.
  variants: {
    "4": {
      title: "4-level paging  (CR3 → PML4 → PDPT → PD → PT)",
      canonicalBit: 47,              // sign-extend VA above bit 47
      levels: [
        { name: "PML4", shift: 39, alt: { linux: "PGD" } },
        { name: "PDPT", shift: 30, alt: { linux: "PUD" } },   // PS here -> 1 GiB page
        { name: "PD",   shift: 21, alt: { linux: "PMD" } },   // PS here -> 2 MiB page
        { name: "PT",   shift: 12, leaf: true, alt: { linux: "PTE" } },
      ],
    },
    "5": {
      title: "5-level paging  (CR3 → PML5 → PML4 → PDPT → PD → PT)",
      canonicalBit: 56,              // 57-bit linear addresses: sign-extend above bit 56
      levels: [
        { name: "PML5", shift: 48, alt: { linux: "PGD" } },
        { name: "PML4", shift: 39, alt: { linux: "P4D" } },
        { name: "PDPT", shift: 30, alt: { linux: "PUD" } },   // PS here -> 1 GiB page
        { name: "PD",   shift: 21, alt: { linux: "PMD" } },   // PS here -> 2 MiB page
        { name: "PT",   shift: 12, leaf: true, alt: { linux: "PTE" } },
      ],
    },
  },
  flags: {
    0:  ["P",   "Present", { linux: "_PAGE_PRESENT" }],
    1:  ["RW",  "Writable", { linux: "_PAGE_RW" }],
    2:  ["US",  "User accessible", { linux: "_PAGE_USER" }],
    3:  ["PWT", "Page-level write-through", { linux: "_PAGE_PWT" }],
    4:  ["PCD", "Page-level cache disable", { linux: "_PAGE_PCD" }],
    5:  ["A",   "Accessed", { linux: "_PAGE_ACCESSED" }],
    6:  ["D",   "Dirty (leaf entries)", { linux: "_PAGE_DIRTY" }],
    7:  ["PS",  "Page size (large page leaf)", { linux: "_PAGE_PSE" }],
    8:  ["G",   "Global (leaf entries)", { linux: "_PAGE_GLOBAL" }],
    63: ["NX",  "No-execute", { linux: "_PAGE_NX" }],
  },
};
