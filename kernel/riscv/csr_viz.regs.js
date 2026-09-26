// RISC-V (RV64) CSR schema, consumed by the shared regviz.html engine.
// Each entry: {name, desc, width?, addr?, flags?{bit:[mn,desc]},
//              fields?[{hi,lo,mn,desc,map?}], decode?(BigInt)->[[k,v],...]}.
window.REGVIZ_TITLE = "RISC-V (RV64) Control and Status Registers";
window.REGS = [
  {
    name: "mstatus", width: 64,
    desc: "Machine status: interrupt enables, privilege bookkeeping and FP/VS state.",
    flags: {
      1:  ["SIE", "Supervisor Interrupt Enable."],
      3:  ["MIE", "Machine Interrupt Enable."],
      5:  ["SPIE", "Supervisor Prior Interrupt Enable (state before a trap)."],
      6:  ["UBE", "User endianness — 1 = big-endian data accesses in U-mode."],
      7:  ["MPIE", "Machine Prior Interrupt Enable (state before a trap)."],
      8:  ["SPP", "Supervisor Previous Privilege — 0 = U, 1 = S."],
      17: ["MPRV", "Modify Privilege — loads/stores use MPP privilege."],
      18: ["SUM", "Permit Supervisor User Memory access."],
      19: ["MXR", "Make eXecutable Readable — loads may read X-only pages."],
      20: ["TVM", "Trap Virtual Memory — traps satp access / SFENCE.VMA in S-mode."],
      21: ["TW", "Timeout Wait — traps WFI executed in lower privilege."],
      22: ["TSR", "Trap SRET — traps SRET executed in S-mode."],
      36: ["SBE", "Supervisor endianness — 1 = big-endian data in S-mode."],
      37: ["MBE", "Machine endianness — 1 = big-endian data in M-mode."],
      38: ["GVA", "Guest Virtual Address — set when a trapping xtval is a guest VA."],
      39: ["MPV", "Machine Previous Virtualization mode."],
      42: ["MDT", "Machine Double-Trap enable (Smdbltrp)."],
      63: ["SD", "State Dirty — some of FS/VS/XS is Dirty."],
    },
    fields: [
      { hi: 10, lo: 9,  mn: "VS", desc: "Vector unit state.",
        map: { "0": "Off", "1": "Initial", "2": "Clean", "3": "Dirty" } },
      { hi: 12, lo: 11, mn: "MPP", desc: "Machine Previous Privilege.",
        map: { "0": "U", "1": "S", "3": "M" } },
      { hi: 14, lo: 13, mn: "FS", desc: "Floating-point unit state.",
        map: { "0": "Off", "1": "Initial", "2": "Clean", "3": "Dirty" } },
      { hi: 16, lo: 15, mn: "XS", desc: "User extension (accelerator) state.",
        map: { "0": "Off", "1": "Initial", "2": "Clean", "3": "Dirty" } },
      { hi: 33, lo: 32, mn: "UXL", desc: "User XLEN.",
        map: { "1": "32", "2": "64", "3": "128" } },
      { hi: 35, lo: 34, mn: "SXL", desc: "Supervisor XLEN.",
        map: { "1": "32", "2": "64", "3": "128" } },
    ],
  },
  {
    name: "sstatus", width: 64,
    desc: "Supervisor status: the S-mode-visible subset of mstatus.",
    flags: {
      1:  ["SIE", "Supervisor Interrupt Enable."],
      5:  ["SPIE", "Supervisor Prior Interrupt Enable (state before a trap)."],
      6:  ["UBE", "User endianness — 1 = big-endian data accesses in U-mode."],
      8:  ["SPP", "Supervisor Previous Privilege — 0 = U, 1 = S."],
      18: ["SUM", "Permit Supervisor User Memory access."],
      19: ["MXR", "Make eXecutable Readable — loads may read X-only pages."],
      63: ["SD", "State Dirty — some of FS/VS/XS is Dirty."],
    },
    fields: [
      { hi: 10, lo: 9,  mn: "VS", desc: "Vector unit state.",
        map: { "0": "Off", "1": "Initial", "2": "Clean", "3": "Dirty" } },
      { hi: 14, lo: 13, mn: "FS", desc: "Floating-point unit state.",
        map: { "0": "Off", "1": "Initial", "2": "Clean", "3": "Dirty" } },
      { hi: 16, lo: 15, mn: "XS", desc: "User extension (accelerator) state.",
        map: { "0": "Off", "1": "Initial", "2": "Clean", "3": "Dirty" } },
      { hi: 33, lo: 32, mn: "UXL", desc: "User XLEN.",
        map: { "1": "32", "2": "64", "3": "128" } },
    ],
  },
  {
    name: "misa", addr: true,
    desc: "ISA and extensions supported: MXL base width plus present extension letters.",
    decode: (v) => {
      const mxl = { "1": "RV32", "2": "RV64", "3": "RV128" };
      const exts = [];
      for (let i = 0; i < 26; i++) {
        if ((v >> BigInt(i)) & 1n) exts.push(String.fromCharCode(65 + i));
      }
      return [
        ["MXL (base width)", mxl[String((v >> 62n) & 3n)] || "Unknown"],
        ["Extensions", exts.length ? exts.join("") : "(none)"],
      ];
    },
  },
  {
    name: "satp", addr: true,
    desc: "Supervisor address translation: paging MODE, ASID and root page-table PPN.",
    decode: (v) => {
      const mode = { "0": "Bare", "8": "Sv39", "9": "Sv48", "10": "Sv57" };
      return [
        ["MODE (63:60)", mode[String((v >> 60n) & 0xFn)] || "Reserved"],
        ["ASID (59:44)", "0x" + ((v >> 44n) & 0xFFFFn).toString(16)],
        ["PPN (43:0)", "0x" + (v & ((1n << 44n) - 1n)).toString(16)],
      ];
    },
  },
  {
    name: "mtvec", addr: true,
    desc: "Machine trap-vector: BASE address plus vectoring MODE in the low 2 bits.",
    decode: (v) => {
      const mode = { "0": "Direct", "1": "Vectored" };
      return [
        ["BASE (63:2)", "0x" + (v & ~0x3n).toString(16)],
        ["MODE (1:0)", mode[String(v & 0x3n)] || "Reserved"],
      ];
    },
  },
  {
    name: "stvec", addr: true,
    desc: "Supervisor trap-vector: BASE address plus vectoring MODE in the low 2 bits.",
    decode: (v) => {
      const mode = { "0": "Direct", "1": "Vectored" };
      return [
        ["BASE (63:2)", "0x" + (v & ~0x3n).toString(16)],
        ["MODE (1:0)", mode[String(v & 0x3n)] || "Reserved"],
      ];
    },
  },
  {
    name: "mie", width: 16,
    desc: "Machine interrupt-enable bits per interrupt source.",
    flags: {
      1:  ["SSIE", "Supervisor Software Interrupt Enable."],
      3:  ["MSIE", "Machine Software Interrupt Enable."],
      5:  ["STIE", "Supervisor Timer Interrupt Enable."],
      7:  ["MTIE", "Machine Timer Interrupt Enable."],
      9:  ["SEIE", "Supervisor External Interrupt Enable."],
      11: ["MEIE", "Machine External Interrupt Enable."],
    },
  },
  {
    name: "mip", width: 16,
    desc: "Machine interrupt-pending bits per interrupt source.",
    flags: {
      1:  ["SSIP", "Supervisor Software Interrupt Pending."],
      3:  ["MSIP", "Machine Software Interrupt Pending."],
      5:  ["STIP", "Supervisor Timer Interrupt Pending."],
      7:  ["MTIP", "Machine Timer Interrupt Pending."],
      9:  ["SEIP", "Supervisor External Interrupt Pending."],
      11: ["MEIP", "Machine External Interrupt Pending."],
    },
  },
  {
    name: "sie", width: 16,
    desc: "Supervisor interrupt-enable bits (S-mode-visible sources).",
    flags: {
      1: ["SSIE", "Supervisor Software Interrupt Enable."],
      5: ["STIE", "Supervisor Timer Interrupt Enable."],
      9: ["SEIE", "Supervisor External Interrupt Enable."],
    },
  },
  {
    name: "sip", width: 16,
    desc: "Supervisor interrupt-pending bits (S-mode-visible sources).",
    flags: {
      1: ["SSIP", "Supervisor Software Interrupt Pending."],
      5: ["STIP", "Supervisor Timer Interrupt Pending."],
      9: ["SEIP", "Supervisor External Interrupt Pending."],
    },
  },
  {
    name: "mideleg", width: 16,
    desc: "Machine interrupt delegation — sources delegated to S-mode handling.",
    flags: {
      1: ["SSI", "Delegate Supervisor Software Interrupt to S-mode."],
      5: ["STI", "Delegate Supervisor Timer Interrupt to S-mode."],
      9: ["SEI", "Delegate Supervisor External Interrupt to S-mode."],
    },
  },
  {
    name: "medeleg", addr: true,
    desc: "Machine exception delegation bitmap — bit N delegates exception cause N to S-mode.",
  },
  {
    name: "mcause", addr: true,
    desc: "Machine trap cause. Interrupt=1 selects an interrupt code, else an exception code.",
    decode: (v) => [
      ["Interrupt (bit 63)", String((v >> 63n) & 1n)],
      ["Code (62:0)", "0x" + (v & ((1n << 63n) - 1n)).toString(16)],
      ["Note", "Interrupt=1 -> interrupt code; Interrupt=0 -> exception code."],
    ],
  },
  {
    name: "scause", addr: true,
    desc: "Supervisor trap cause. Interrupt=1 selects an interrupt code, else an exception code.",
    decode: (v) => [
      ["Interrupt (bit 63)", String((v >> 63n) & 1n)],
      ["Code (62:0)", "0x" + (v & ((1n << 63n) - 1n)).toString(16)],
      ["Note", "Interrupt=1 -> interrupt code; Interrupt=0 -> exception code."],
    ],
  },
  {
    name: "mepc", addr: true,
    desc: "Machine exception program counter — address to return to after an M-mode trap.",
  },
  {
    name: "sepc", addr: true,
    desc: "Supervisor exception program counter — address to return to after an S-mode trap.",
  },
  {
    name: "mtval", addr: true,
    desc: "Machine trap value — fault address or offending instruction bits for the trap.",
  },
  {
    name: "stval", addr: true,
    desc: "Supervisor trap value — fault address or offending instruction bits for the trap.",
  },
];
