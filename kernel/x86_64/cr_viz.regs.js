// x86_64 control-register schema, consumed by the shared regviz.html engine.
// Each entry: {name, desc, width?, addr?, flags?{bit:[mn,desc]},
//              fields?[{hi,lo,mn,desc,map?}], decode?(BigInt)->[[k,v],...]}.
window.REGVIZ_TITLE = "x86_64 Control Registers";
window.REGS = [
  {
    name: "CR0", width: 32,
    desc: "System control flags: protection, paging and the FPU/cache mode.",
    flags: {
      0:  ["PE", "Protection Enable — 1 = protected mode."],
      1:  ["MP", "Monitor Coprocessor — controls WAIT/FWAIT with TS."],
      2:  ["EM", "Emulation — 1 = no x87 FPU present, x87 traps."],
      3:  ["TS", "Task Switched — set on task switch to lazily save FPU state."],
      4:  ["ET", "Extension Type — reserved as 1 on modern CPUs."],
      5:  ["NE", "Numeric Error — 1 = native x87 error reporting (#MF)."],
      16: ["WP", "Write Protect — 1 = supervisor cannot write read-only pages."],
      18: ["AM", "Alignment Mask — enables #AC alignment checks with EFLAGS.AC."],
      29: ["NW", "Not Write-through — legacy cache write policy."],
      30: ["CD", "Cache Disable — 1 = caching disabled."],
      31: ["PG", "Paging — 1 = paging enabled (requires PE)."],
    },
  },
  {
    name: "CR4", width: 32,
    desc: "Feature enable flags: PAE, page-global, SMEP/SMAP, VMX and more.",
    flags: {
      0:  ["VME", "Virtual-8086 Mode Extensions."],
      1:  ["PVI", "Protected-Mode Virtual Interrupts."],
      2:  ["TSD", "Time Stamp Disable — RDTSC restricted to ring 0."],
      3:  ["DE", "Debugging Extensions."],
      4:  ["PSE", "Page Size Extensions — enables 4 MiB pages (32-bit paging)."],
      5:  ["PAE", "Physical Address Extension — required for long mode."],
      6:  ["MCE", "Machine-Check Enable."],
      7:  ["PGE", "Page Global Enable — global TLB entries survive CR3 loads."],
      8:  ["PCE", "Performance-Counter Enable for RDPMC."],
      9:  ["OSFXSR", "OS support for FXSAVE/FXRSTOR and SSE."],
      10: ["OSXMMEXCPT", "OS support for unmasked SIMD FP exceptions (#XM)."],
      11: ["UMIP", "User-Mode Instruction Prevention (SGDT/SIDT/etc.)."],
      12: ["LA57", "5-level paging (57-bit linear addresses)."],
      13: ["VMXE", "VMX Enable."],
      14: ["SMXE", "SMX Enable."],
      16: ["FSGSBASE", "Enables RD/WR FS/GS BASE instructions."],
      17: ["PCIDE", "Process-Context Identifiers Enable."],
      18: ["OSXSAVE", "XSAVE and processor extended states enable."],
      19: ["KL", "Key Locker Enable."],
      20: ["SMEP", "Supervisor Mode Execution Prevention."],
      21: ["SMAP", "Supervisor Mode Access Prevention."],
      22: ["PKE", "Protection Keys for user pages (PKU)."],
      23: ["CET", "Control-flow Enforcement Technology."],
      24: ["PKS", "Protection Keys for supervisor pages."],
    },
  },
  {
    name: "EFER", width: 16,
    desc: "Extended Feature Enable MSR (0xC0000080) — long mode, NX, SYSCALL.",
    flags: {
      0:  ["SCE", "System Call Extensions — enables SYSCALL/SYSRET."],
      8:  ["LME", "Long Mode Enable."],
      10: ["LMA", "Long Mode Active (read-only status)."],
      11: ["NXE", "No-Execute Enable — enables the NX page bit."],
      12: ["SVME", "Secure Virtual Machine Enable (AMD-V)."],
      13: ["LMSLE", "Long Mode Segment Limit Enable (AMD)."],
      14: ["FFXSR", "Fast FXSAVE/FXRSTOR."],
      15: ["TCE", "Translation Cache Extension."],
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

// 4-level paging tree, walked live from CR3 via the shared page-table engine.
// Enables the "Page tables" section: click a node to read the pointed-to table
// (512 8-byte entries) over the gdb/QEMU monitor and expand the next level.
window.REGVIZ_PAGETABLE = {
  title: "4-level paging  (CR3 → PML4 → PDPT → PD → PT)",
  baseReg: "CR3",                    // root table base comes from this register
  baseMask: "0x000ffffffffff000",    // physical base = bits 12..51 of an entry
  presentBit: 0,                     // bit 0 = Present
  largePageBit: 7,                   // bit 7 = PS: a leaf 1 GiB (PDPT) / 2 MiB (PD) page
  canonicalBit: 47,                  // sign-extend VA above bit 47
  entriesPerTable: 512,
  levels: [
    { name: "PML4", shift: 39 },
    { name: "PDPT", shift: 30 },     // PS here -> 1 GiB page
    { name: "PD",   shift: 21 },     // PS here -> 2 MiB page
    { name: "PT",   shift: 12, leaf: true },
  ],
  flags: {
    0:  ["P",   "Present"],
    1:  ["RW",  "Writable"],
    2:  ["US",  "User accessible"],
    3:  ["PWT", "Page-level write-through"],
    4:  ["PCD", "Page-level cache disable"],
    5:  ["A",   "Accessed"],
    6:  ["D",   "Dirty (leaf entries)"],
    7:  ["PS",  "Page size (large page leaf)"],
    8:  ["G",   "Global (leaf entries)"],
    63: ["NX",  "No-execute"],
  },
};
