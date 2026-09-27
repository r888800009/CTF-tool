// MIPS32 CP0 (System Control Coprocessor) register schema,
// consumed by the shared regviz.html engine.
// Each entry: {name, desc, width?, addr?, flags?{bit:[mn,desc]},
//              fields?[{hi,lo,mn,desc,map?}], decode?(BigInt)->[[k,v],...]}.
window.REGVIZ_TITLE = "MIPS CP0 System Control Registers";
window.REGS = [
  {
    name: "Status", width: 32,
    desc: "CP0 r12 — processor status: interrupt enables, privilege mode and CU bits.",
    flags: {
      0:  ["IE", "Interrupt Enable — 1 = interrupts enabled."],
      1:  ["EXL", "Exception Level — 1 = in exception handler."],
      2:  ["ERL", "Error Level — 1 = in error handler (reset/NMI/cache error)."],
      5:  ["UX", "Enables 64-bit addressing/instructions in user mode."],
      6:  ["SX", "Enables 64-bit addressing/instructions in supervisor mode."],
      7:  ["KX", "Enables 64-bit addressing/instructions in kernel mode."],
      8:  ["IM0", "Interrupt Mask 0 — software interrupt 0."],
      9:  ["IM1", "Interrupt Mask 1 — software interrupt 1."],
      10: ["IM2", "Interrupt Mask 2 — hardware interrupt."],
      11: ["IM3", "Interrupt Mask 3 — hardware interrupt."],
      12: ["IM4", "Interrupt Mask 4 — hardware interrupt."],
      13: ["IM5", "Interrupt Mask 5 — hardware interrupt."],
      14: ["IM6", "Interrupt Mask 6 — hardware interrupt."],
      15: ["IM7", "Interrupt Mask 7 — hardware interrupt / timer."],
      19: ["NMI", "1 = last exception entry was a non-maskable interrupt."],
      20: ["SR", "Soft reset — 1 = last reset was a soft reset."],
      21: ["TS", "TLB Shutdown — 1 = a TLB multiple-match was detected."],
      22: ["BEV", "Bootstrap Exception Vectors — 1 = ROM (bootstrap) vectors."],
      25: ["RE", "Reverse endian — reverses endianness in user mode."],
      26: ["FR", "1 = 32 double-width floating-point registers."],
      27: ["RP", "Reduced Power — enables reduced-power operating mode."],
      28: ["CU0", "Coprocessor 0 Usable."],
      29: ["CU1", "Coprocessor 1 Usable (FPU)."],
      30: ["CU2", "Coprocessor 2 Usable."],
      31: ["CU3", "Coprocessor 3 Usable."],
    },
    fields: [
      { hi: 4, lo: 3, mn: "KSU", desc: "Operating mode / privilege level.",
        map: { "0": "Kernel", "1": "Supervisor", "2": "User" } },
    ],
  },
  {
    name: "Cause", width: 32,
    desc: "CP0 r13 — cause of the most recent exception plus pending interrupts.",
    flags: {
      8:  ["IP0", "Interrupt Pending 0 — software interrupt 0."],
      9:  ["IP1", "Interrupt Pending 1 — software interrupt 1."],
      10: ["IP2", "Interrupt Pending 2 — hardware interrupt."],
      11: ["IP3", "Interrupt Pending 3 — hardware interrupt."],
      12: ["IP4", "Interrupt Pending 4 — hardware interrupt."],
      13: ["IP5", "Interrupt Pending 5 — hardware interrupt."],
      14: ["IP6", "Interrupt Pending 6 — hardware interrupt."],
      15: ["IP7", "Interrupt Pending 7 — hardware interrupt / timer."],
      22: ["WP", "Watch Pending — a deferred watch exception is pending."],
      23: ["IV", "1 = use the special interrupt vector (not the general one)."],
      31: ["BD", "Branch delay — 1 = exception victim was in a branch delay slot."],
    },
    fields: [
      { hi: 6, lo: 2, mn: "ExcCode", desc: "Exception code.",
        map: {
          "0": "Int", "4": "AdEL", "5": "AdES", "6": "IBE", "7": "DBE",
          "8": "Sys", "9": "Bp", "10": "RI", "11": "CpU", "12": "Ov",
          "13": "Tr", "15": "FPE",
        } },
      { hi: 29, lo: 28, mn: "CE", desc: "Coprocessor unit for a CpU exception." },
    ],
    decode: (v) => {
      const code = Number((v >> 2n) & 0x1Fn);
      const names = {
        0: "Int (interrupt)", 4: "AdEL (address error, load/fetch)",
        5: "AdES (address error, store)", 6: "IBE (bus error, fetch)",
        7: "DBE (bus error, load/store)", 8: "Sys (syscall)",
        9: "Bp (breakpoint)", 10: "RI (reserved instruction)",
        11: "CpU (coprocessor unusable)", 12: "Ov (arithmetic overflow)",
        13: "Tr (trap)", 15: "FPE (floating-point exception)",
      };
      return [
        ["ExcCode", String(code) + " — " + (names[code] || "reserved")],
        ["Branch delay (BD)", String((v >> 31n) & 1n)],
      ];
    },
  },
  {
    name: "EPC", addr: true,
    desc: "CP0 r14 — Exception Program Counter: address to resume at after an exception.",
  },
  {
    name: "BadVAddr", addr: true,
    desc: "CP0 r8 — virtual address of the most recent address-related exception.",
  },
  {
    name: "EntryHi", width: 32,
    desc: "CP0 r10 — high half of a TLB entry: VPN2 tag and current ASID.",
    fields: [
      { hi: 31, lo: 13, mn: "VPN2", desc: "Virtual page number of an even/odd page pair." },
      { hi: 7, lo: 0, mn: "ASID", desc: "Address Space Identifier of the current process." },
    ],
    decode: (v) => [
      ["VPN2 (bits 31:13)", "0x" + ((v >> 13n) & 0x7FFFFn).toString(16)],
      ["ASID (bits 7:0)", "0x" + (v & 0xFFn).toString(16)],
    ],
  },
  {
    name: "EntryLo0", width: 32,
    desc: "CP0 r2 — low half of a TLB entry for the even physical page.",
    flags: {
      0: ["G", "Global — entry ignores ASID when set in both EntryLo0/1."],
      1: ["V", "Valid — 1 = the mapping is valid."],
      2: ["D", "Dirty / writable — 1 = writes are permitted."],
    },
    fields: [
      { hi: 5, lo: 3, mn: "C", desc: "Cache coherency attribute." },
      { hi: 25, lo: 6, mn: "PFN", desc: "Page frame number (physical page)." },
    ],
  },
  {
    name: "EntryLo1", width: 32,
    desc: "CP0 r3 — low half of a TLB entry for the odd physical page.",
    flags: {
      0: ["G", "Global — entry ignores ASID when set in both EntryLo0/1."],
      1: ["V", "Valid — 1 = the mapping is valid."],
      2: ["D", "Dirty / writable — 1 = writes are permitted."],
    },
    fields: [
      { hi: 5, lo: 3, mn: "C", desc: "Cache coherency attribute." },
      { hi: 25, lo: 6, mn: "PFN", desc: "Page frame number (physical page)." },
    ],
  },
  {
    name: "PageMask", width: 32,
    desc: "CP0 r5 — TLB page-size mask; selects the page size for an entry.",
    fields: [
      { hi: 24, lo: 13, mn: "MASK", desc: "Comparison mask — larger mask = larger page." },
    ],
  },
  {
    name: "Index", addr: true,
    desc: "CP0 r0 — TLB index used by TLBR/TLBWI; high bit flags a failed TLBP probe.",
  },
  {
    name: "Random", addr: true,
    desc: "CP0 r1 — free-running TLB index used by TLBWR for random replacement.",
  },
  {
    name: "Wired", addr: true,
    desc: "CP0 r6 — boundary of wired (non-replaceable) TLB entries.",
  },
  {
    name: "Context", addr: true,
    desc: "CP0 r4 — pointer to a page-table entry for the current bad virtual address.",
  },
  {
    name: "Config", addr: true,
    desc: "CP0 r16 — cache and architecture configuration (cache sizes, endianness, MMU type).",
  },
];
